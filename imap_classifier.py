#!/usr/bin/env python3
"""
IMAP Email Auto-Classifier

Connects to an IMAP server and automatically moves emails from INBOX
into sub-folders based on the "From" display name. Designed for RSS2EMAIL
mailboxes with large INBOXes.

The email address part is intentionally ignored (often bogus like pi@localhost).
Folder names are derived from the display name with aggressive sanitization:
  - "<author>" patterns stripped
  - Commas, braces {}, colons, angle brackets removed
  - Chinese/Unicode characters preserved
  - Dangerous IMAP/filesystem characters escaped

Usage:
    1. Copy config.example.json to config.json and fill in your details
    2. Run: python imap_classifier.py
    3. Or run with --dry-run to preview without moving anything
"""

import imaplib
import email
import email.header
import re
import json
import argparse
import logging
import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "host": "imap.example.com",
    "port": 993,
    "username": "you@example.com",
    "password": "your-password",
    "use_ssl": True,
    "source_folder": "INBOX",
    "folder_prefix": "INBOX",           # e.g. "INBOX" → creates "INBOX/FeedName"
    "folder_separator": "",              # auto-detected if empty
    "batch_size": 100,                   # UIDs processed per MOVE/COPY batch
    "max_folder_name_length": 80,
    "name_to_folder_overrides": {
        # Manual overrides: display-name substring → folder name
        # "Above the Law": "Above the Law",
    },
    "skip_names": [
        # List of display-name substrings to leave in INBOX
    ],
    "fallback_folder": "_Unsorted",     # When display name is empty/unparseable
}

CONFIG_FILE = "config.json"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Display Name Parsing & Sanitization
# ---------------------------------------------------------------------------


def decode_header_value(raw: Optional[str]) -> str:
    """Decode an RFC2047-encoded header into a plain string."""
    if raw is None:
        return ""
    parts = email.header.decode_header(raw)
    decoded_parts = []
    for data, charset in parts:
        if isinstance(data, bytes):
            decoded_parts.append(data.decode(charset or "utf-8", errors="replace"))
        else:
            decoded_parts.append(data)
    return " ".join(decoded_parts).strip()


def extract_display_name(msg: email.message.Message) -> str:
    """
    Extract only the display name from the From header.
    Email address is intentionally ignored (often bogus in RSS2EMAIL).

    Examples:
        "Above the Law: Joe Patrice" <pi@localhost>   → Above the Law: Joe Patrice
        "Hacker News: <author>" <pi@localhost>         → Hacker News: <author>
        pi@localhost                                   → ""  (no display name)
    """
    raw_from = decode_header_value(msg.get("From", ""))

    # Match: "Display Name" <addr> or Display Name <addr>
    # Greedy match on display name, then angle-bracket email at the end
    match = re.match(r'^"?(.*?)"?\s*<[^>]*>\s*$', raw_from)
    if match:
        return match.group(1).strip()

    # If it looks like a bare email address, return empty
    if re.match(r'^\S+@\S+$', raw_from.strip()):
        return ""

    return raw_from.strip()


def sanitize_to_folder_name(display_name: str, max_len: int = 80) -> str:
    """
    Convert a raw display name into a safe IMAP folder name.

    Rules applied in order:
        1. Strip any "<...>" segments (e.g. "<author>", "<someone>")
        2. Remove characters: , { } : ; " ' ` * % \\ /
           (security-sensitive or IMAP-special)
        3. Replace newlines/tabs with space
        4. Collapse multiple spaces / leading-trailing whitespace
        5. Strip leading/trailing dots, dashes, underscores
        6. Truncate to max_len
        7. Chinese / other Unicode letters are preserved

    Examples:
        "Above the Law: Joe Patrice"                    → "Above the Law Joe Patrice"
        "Hacker News: <author>"                         → "Hacker News"
        "杰哥的{运维，编程，调板子}小笔记: <author>"     → "杰哥的运维编程调板子小笔记"
        "奇客Solidot–传递最新科技情报: <author>"         → "奇客Solidot–传递最新科技情报"
    """
    s = display_name

    # 1. Strip <...> patterns (like <author>, <someone@foo>)
    s = re.sub(r'<[^>]*>', '', s)

    # 2. Remove dangerous / noisy punctuation
    #    Keep: letters (any script), digits, spaces, hyphen, underscore, dot,
    #          parentheses, and common Unicode punctuation like – —
    #    Remove: , { } : ; " ' ` * % \ / | ! @ # $ ^ & = + [ ] ? ~
    s = re.sub(r'[,{}:;\"\'\`\*%\\/|!@#\$\^&=\+\[\]?~]', '', s)

    # Also remove fullwidth commas/colons and Chinese-specific punctuation
    # that might sneak in: ，：｛｝「」【】
    s = re.sub(r'[，：｛｝「」【】『』〈〉《》]', '', s)

    # 3. Normalize whitespace
    s = re.sub(r'[\r\n\t]+', ' ', s)
    s = re.sub(r'\s+', ' ', s)
    s = s.strip()

    # 4. Strip leading/trailing dots, dashes, underscores (filesystem safety)
    s = s.strip('.-_ ')

    # 5. Truncate
    if len(s) > max_len:
        s = s[:max_len].rstrip()

    return s


def display_name_to_feed_name(display_name: str) -> str:
    """
    Extract the feed/site name from the display name, dropping per-article
    author information.

    RSS2EMAIL typically formats From as:
        "Feed Title: Article Author" <addr>
        "Feed Title" <addr>

    We want to group by feed title, so we take everything before the FIRST
    colon (if present) as the feed name. If there's no colon, use the whole
    display name.

    Applied BEFORE sanitization so the colon is still present as a delimiter.
    """
    # First strip <...> so "Hacker News: <author>" → "Hacker News: "
    s = re.sub(r'<[^>]*>', '', display_name).strip()

    # Split on first colon (ASCII or fullwidth)
    match = re.split(r'[:：]', s, maxsplit=1)
    feed_part = match[0].strip()

    return feed_part if feed_part else s


# ---------------------------------------------------------------------------
# IMAP operations
# ---------------------------------------------------------------------------


class IMAPClassifier:
    def __init__(self, cfg: dict, dry_run: bool = False):
        self.cfg = cfg
        self.dry_run = dry_run
        self.conn: Optional[imaplib.IMAP4] = None
        self.separator: str = cfg.get("folder_separator") or "/"
        self.existing_folders: set[str] = set()

    # -- connection ----------------------------------------------------------

    def connect(self):
        if self.cfg.get("use_ssl", True):
            self.conn = imaplib.IMAP4_SSL(self.cfg["host"], self.cfg.get("port", 993))
        else:
            self.conn = imaplib.IMAP4(self.cfg["host"], self.cfg.get("port", 143))
        log.info("Connected to %s:%s", self.cfg["host"], self.cfg.get("port"))
        self.conn.login(self.cfg["username"], self.cfg["password"])
        log.info("Logged in as %s", self.cfg["username"])
        self._detect_separator()
        self._cache_existing_folders()

    def disconnect(self):
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
            try:
                self.conn.logout()
            except Exception:
                pass
            log.info("Disconnected.")

    def _detect_separator(self):
        """Auto-detect the IMAP hierarchy separator."""
        if self.cfg.get("folder_separator"):
            self.separator = self.cfg["folder_separator"]
            return
        status, data = self.conn.list('""', '*')
        if status == "OK" and data and data[0]:
            match = re.search(rb'"(.)"', data[0])
            if match:
                self.separator = match.group(1).decode()
                log.info("Auto-detected hierarchy separator: %r", self.separator)
                return
        self.separator = "/"

    def _cache_existing_folders(self):
        """Fetch the list of existing IMAP folders."""
        status, data = self.conn.list('""', '*')
        if status != "OK":
            return
        for item in data:
            if item is None:
                continue
            # Parse LIST response, e.g.: (\\HasChildren) "/" "INBOX/feeds"
            match = re.match(rb'\(.*?\)\s+"?(.)"?\s+(.+)$', item)
            if match:
                raw_name = match.group(2).strip(b'"').strip()
                try:
                    folder = raw_name.decode("utf-8")
                except UnicodeDecodeError:
                    folder = raw_name.decode("latin-1", errors="replace")
                self.existing_folders.add(folder)
        log.debug("Existing folders: %s", self.existing_folders)

    def _full_folder_path(self, folder_name: str) -> str:
        prefix = self.cfg.get("folder_prefix", "INBOX")
        if prefix:
            return f"{prefix}{self.separator}{folder_name}"
        return folder_name

    def _encode_folder_name(self, folder_path: str) -> bytes:
        """
        Encode folder name to modified UTF-7 for IMAP (RFC 3501 §5.1.3).
        Only encodes non-ASCII segments; ASCII passes through.
        """
        import base64
        result = bytearray()
        non_ascii_buf = ""

        def flush_non_ascii():
            nonlocal non_ascii_buf
            if non_ascii_buf:
                utf16 = non_ascii_buf.encode("utf-16-be")
                b64 = base64.b64encode(utf16).rstrip(b"=")
                result.extend(b"&")
                result.extend(b64.replace(b"/", b","))
                result.extend(b"-")
                non_ascii_buf = ""

        for ch in folder_path:
            if 0x20 <= ord(ch) <= 0x7E:
                flush_non_ascii()
                if ch == "&":
                    result.extend(b"&-")
                else:
                    result.append(ord(ch))
            else:
                non_ascii_buf += ch

        flush_non_ascii()
        return bytes(result)

    def _ensure_folder(self, folder_path: str):
        """Create the folder if it doesn't exist yet."""
        if folder_path in self.existing_folders:
            return
        if self.dry_run:
            log.info("[DRY RUN] Would create folder: %s", folder_path)
            self.existing_folders.add(folder_path)
            return

        encoded = self._encode_folder_name(folder_path)
        quoted = b'"' + encoded + b'"'
        status, data = self.conn._simple_command("CREATE", quoted.decode("ascii", errors="surrogateescape"))
        if status == "OK":
            log.info("Created folder: %s", folder_path)
            self.conn._simple_command("SUBSCRIBE", quoted.decode("ascii", errors="surrogateescape"))
        else:
            log.warning("Could not create folder %s: %s (may already exist)", folder_path, data)
        self.existing_folders.add(folder_path)

    # -- resolve folder name -------------------------------------------------

    def _resolve_folder_name(self, display_name: str) -> Optional[str]:
        """
        Given a raw display name, return the target folder name or None to skip.
        """
        skip_names = self.cfg.get("skip_names", [])
        for pattern in skip_names:
            if pattern.lower() in display_name.lower():
                return None

        # Check overrides (substring match, case-insensitive)
        overrides = self.cfg.get("name_to_folder_overrides", {})
        for pattern, folder in overrides.items():
            if pattern.lower() in display_name.lower():
                return folder

        # Extract feed name (before first colon), then sanitize
        feed_name = display_name_to_feed_name(display_name)
        sanitized = sanitize_to_folder_name(feed_name, self.cfg.get("max_folder_name_length", 80))

        if not sanitized:
            return self.cfg.get("fallback_folder", "_Unsorted")

        return sanitized

    # -- classification ------------------------------------------------------

    def classify(self):
        """Main entry point: fetch UIDs, group by From display name, move."""
        source = self.cfg.get("source_folder", "INBOX")
        status, data = self.conn.select(f'"{source}"')
        if status != "OK":
            log.error("Cannot select %s: %s", source, data)
            return
        num_messages = int(data[0])
        log.info("Folder '%s' contains %d messages.", source, num_messages)
        if num_messages == 0:
            return

        # Fetch all UIDs
        status, data = self.conn.uid("SEARCH", None, "ALL")
        if status != "OK":
            log.error("UID SEARCH failed: %s", data)
            return

        uids = data[0].split()
        log.info("Found %d UIDs to process.", len(uids))

        # Group UIDs by target folder
        folder_uids: dict[str, list[bytes]] = defaultdict(list)
        skipped = 0
        fetch_batch_size = 50  # UIDs per FETCH call
        total = len(uids)

        for i in range(0, total, fetch_batch_size):
            batch = uids[i:i + fetch_batch_size]
            uid_set = b",".join(batch)
            status, msg_data = self.conn.uid(
                "FETCH", uid_set, "(BODY.PEEK[HEADER.FIELDS (FROM)])"
            )
            if status != "OK":
                log.warning("FETCH failed for batch starting at %d", i)
                continue

            current_uid = None
            for item in msg_data:
                if isinstance(item, tuple):
                    header_info = item[0].decode(errors="replace")
                    uid_match = re.search(r'UID\s+(\d+)', header_info)
                    if uid_match:
                        current_uid = uid_match.group(1).encode()

                    msg = email.message_from_bytes(item[1])
                    display_name = extract_display_name(msg)

                    folder_name = self._resolve_folder_name(display_name)
                    if folder_name is None:
                        skipped += 1
                        continue

                    if not display_name:
                        folder_name = self.cfg.get("fallback_folder", "_Unsorted")

                    folder_path = self._full_folder_path(folder_name)

                    if current_uid:
                        folder_uids[folder_path].append(current_uid)
                        log.debug(
                            "UID %s: %r → %s",
                            current_uid.decode(), display_name, folder_path,
                        )

            processed = min(i + fetch_batch_size, total)
            if processed % 500 == 0 or processed == total:
                log.info("Scanned %d / %d messages...", processed, total)

        total_to_move = sum(len(v) for v in folder_uids.values())
        log.info(
            "Classification complete: %d folders, %d to move, %d skipped.",
            len(folder_uids), total_to_move, skipped,
        )

        # Print summary sorted by message count
        log.info("--- Summary ---")
        for folder, uid_list in sorted(folder_uids.items(), key=lambda x: -len(x[1])):
            log.info("  %-60s  %5d msgs", folder, len(uid_list))
        log.info("---------------")

        if total_to_move == 0:
            log.info("Nothing to move.")
            return

        # Move messages in batches
        move_batch_size = self.cfg.get("batch_size", 100)
        moved_total = 0
        for folder_path, uid_list in folder_uids.items():
            self._ensure_folder(folder_path)
            for j in range(0, len(uid_list), move_batch_size):
                batch = uid_list[j:j + move_batch_size]
                uid_set = b",".join(batch)
                self._move_uids(uid_set, folder_path)
                moved_total += len(batch)
                if moved_total % 500 == 0:
                    log.info("Moved %d / %d messages...", moved_total, total_to_move)

        # Expunge to finalize deletions from INBOX
        if not self.dry_run:
            log.info("Expunging deleted messages from %s ...", source)
            self.conn.expunge()

        log.info("Done! Moved %d messages into %d folders.", moved_total, len(folder_uids))

    def _move_uids(self, uid_set: bytes, dest_folder: str):
        """Move messages by UID using MOVE or COPY+DELETE fallback."""
        encoded_dest = self._encode_folder_name(dest_folder)
        quoted_dest = b'"' + encoded_dest + b'"'
        quoted_dest_str = quoted_dest.decode("ascii", errors="surrogateescape")

        if self.dry_run:
            count = len(uid_set.split(b","))
            log.info("[DRY RUN] Would move %d messages → %s", count, dest_folder)
            return

        # Try MOVE first (RFC 6851)
        try:
            status, data = self.conn.uid("MOVE", uid_set, quoted_dest_str)
            if status == "OK":
                return
        except (imaplib.IMAP4.error, AttributeError):
            pass

        # Fallback: COPY + mark \Deleted
        status, data = self.conn.uid("COPY", uid_set, quoted_dest_str)
        if status == "OK":
            self.conn.uid("STORE", uid_set, "+FLAGS", "(\\Deleted)")
        else:
            log.error("COPY to %s failed: %s", dest_folder, data)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Auto-classify IMAP INBOX emails into folders by From display name.",
        epilog="""
Examples:
  %(prog)s --dry-run          Preview moves without changing anything
  %(prog)s                    Run classification
  %(prog)s -c myconfig.json   Use alternate config file
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--config", "-c", default=CONFIG_FILE,
        help="Path to JSON config file (default: %(default)s)",
    )
    parser.add_argument(
        "--dry-run", "-n", action="store_true",
        help="Preview classification without moving any messages.",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging.",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load or create config
    cfg_path = Path(args.config)
    if not cfg_path.exists():
        log.warning("Config file '%s' not found – creating template. Please edit it.", args.config)
        cfg_path.write_text(json.dumps(DEFAULT_CONFIG, indent=2, ensure_ascii=False))
        sys.exit(1)

    with open(cfg_path) as f:
        user_cfg = json.load(f)
    cfg = {**DEFAULT_CONFIG, **user_cfg}

    classifier = IMAPClassifier(cfg, dry_run=args.dry_run)

    try:
        classifier.connect()
        classifier.classify()
    except KeyboardInterrupt:
        log.info("Interrupted by user.")
    except Exception:
        log.exception("Fatal error")
        sys.exit(1)
    finally:
        classifier.disconnect()


if __name__ == "__main__":
    main()