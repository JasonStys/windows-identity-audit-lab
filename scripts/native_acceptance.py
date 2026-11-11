"""Real frozen widget/core/history/export/unknown-state acceptance on explicit synthetic profiles. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: capture — line 106
# parameter: target — line 106
# parameter: window — line 106
# variable: load — line 112
# variable: gdi — line 113
# variable: user — line 113
# variable: pointer — line 114
# variable: arguments — line 115
# variable: library — line 115
# variable: name — line 115
# variable: result — line 115
# variable: function — line 141
# attribute: argtypes — line 142
# attribute: restype — line 142
# variable: handle — line 145
# variable: rectangle — line 146
# variable: height — line 149
# variable: width — line 149
# variable: source — line 152
# variable: destination — line 153
# variable: bitmap — line 154
# variable: previous — line 155
# variable: pixels — line 160
# variable: header — line 161
# variable: raw — line 179
# variable: scanlines — line 180
# variable: row — line 181
# variable: column — line 183
# variable: offset — line 184
# definition: chunk — line 187
# parameter: data — line 187
# parameter: name — line 187
# definition: oracle — line 209
# parameter: files — line 209
# parameter: index — line 209
# variable: value — line 212
# variable: value — line 221
# variable: by_sid — line 222
# variable: row — line 222
# variable: user — line 223
# variable: value — line 241
# definition: exercise — line 245
# parameter: output — line 245
# parameter: reopen — line 245
# parameter: window — line 245
# variable: deadline — line 248
# variable: receipt — line 249
# variable: expected_runs — line 263
# definition: persist — line 265
# definition: finish — line 271
# parameter: failed — line 271
# attribute: acceptance_result — line 274
# variable: name — line 278
# variable: raw — line 278
# variable: row — line 280
# definition: checked — line 285
# parameter: callback — line 285
# definition: wait — line 293
# parameter: callback — line 293
# definition: layout — line 303
# variable: original — line 305
# variable: button — line 328
# variable: name — line 328
# variable: button — line 338
# definition: rejected — line 356
# definition: export_and_reject — line 363
# variable: parent — line 367
# variable: original — line 369
# variable: target — line 374
# variable: path — line 375
# definition: completed — line 386
# parameter: index — line 386
# variable: files — line 390
# variable: desired — line 395
# definition: start — line 433
# parameter: index — line 433
# variable: field — line 439
# variable: source — line 439
# variable: imported — line 443
# definition: begin — line 452
# variable: identity — line 456
# END CODE MAP

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import struct
import sys
import time
import zlib
from pathlib import Path
from typing import TYPE_CHECKING, Any

from identitylab import desktop_project as project
from identitylab.desktop_io import json_value

if TYPE_CHECKING:
    from identitylab.desktop import Workbench


def capture(window: Workbench, target: Path) -> None:
    """Capture only this owned synthetic Tk window via PrintWindow, never the user's whole desktop."""
    if sys.platform != "win32":
        raise OSError("native screenshot acceptance targets Windows")
    from ctypes import wintypes

    load = ctypes.WinDLL
    user, gdi = load("user32", use_last_error=True), load("gdi32", use_last_error=True)
    pointer = ctypes.c_void_p
    for library, name, arguments, result in [
        (user, "GetAncestor", [pointer, ctypes.c_uint], pointer),
        (user, "GetWindowDC", [pointer], pointer),
        (gdi, "CreateCompatibleDC", [pointer], pointer),
        (gdi, "CreateCompatibleBitmap", [pointer, ctypes.c_int, ctypes.c_int], pointer),
        (gdi, "SelectObject", [pointer, pointer], pointer),
        (gdi, "DeleteObject", [pointer], ctypes.c_int),
        (gdi, "DeleteDC", [pointer], ctypes.c_int),
        (user, "ReleaseDC", [pointer, pointer], ctypes.c_int),
        (user, "PrintWindow", [pointer, pointer, ctypes.c_uint], ctypes.c_int),
        (user, "GetWindowRect", [pointer, ctypes.POINTER(wintypes.RECT)], ctypes.c_int),
        (
            gdi,
            "GetDIBits",
            [
                pointer,
                pointer,
                ctypes.c_uint,
                ctypes.c_uint,
                pointer,
                pointer,
                ctypes.c_uint,
            ],
            ctypes.c_int,
        ),
    ]:
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, result
    # Flush this owned native window's pending control messages before reading its pixels.
    window.root.update()
    handle = user.GetAncestor(window.root.winfo_id(), 2)
    rectangle = wintypes.RECT()
    if not user.GetWindowRect(handle, ctypes.byref(rectangle)):
        raise OSError("owned window bounds unavailable")
    width, height = rectangle.right - rectangle.left, rectangle.bottom - rectangle.top
    if not 1 <= width <= 4096 or not 1 <= height <= 4096:
        raise OSError("owned screenshot outside bounded dimensions")
    source = user.GetWindowDC(handle)
    destination = gdi.CreateCompatibleDC(source)
    bitmap = gdi.CreateCompatibleBitmap(source, width, height)
    previous = gdi.SelectObject(destination, bitmap)
    try:
        if not user.PrintWindow(handle, destination, 2):
            raise OSError("owned window rendering unavailable")
        gdi.SelectObject(destination, previous)
        pixels = ctypes.create_string_buffer(width * height * 4)
        header = ctypes.create_string_buffer(
            struct.pack(
                "<IiiHHIIiiII",
                40,
                width,
                -height,
                1,
                32,
                0,
                width * height * 4,
                0,
                0,
                0,
                0,
            )
        )
        if gdi.GetDIBits(source, bitmap, 0, height, pixels, header, 0) != height:
            raise OSError("owned screenshot pixels incomplete")
        raw = pixels.raw
        scanlines = bytearray()
        for row in range(height):
            scanlines.append(0)
            for column in range(width):
                offset = (row * width + column) * 4
                scanlines.extend((raw[offset + 2], raw[offset + 1], raw[offset]))

        def chunk(name: bytes, data: bytes) -> bytes:
            """Encode a bounded standard PNG chunk with its actual CRC."""
            return (
                struct.pack(">I", len(data))
                + name
                + data
                + struct.pack(">I", zlib.crc32(name + data))
            )

        target.write_bytes(
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(scanlines)))
            + chunk(b"IEND", b"")
        )
    finally:
        gdi.SelectObject(destination, previous)
        gdi.DeleteObject(bitmap)
        gdi.DeleteDC(destination)
        user.ReleaseDC(handle, source)


def oracle(index: int, files: dict[str, bytes]) -> None:
    """Hardcoded known SID/control expectations; never manufacture a report or replace the actual analysis."""
    if index == 0:
        value = json_value(files["review.json"])
        assert value["complete"] is True and len(value["findings"]) == 3
        assert set(files) == {
            "review.json",
            "review.html",
            "manifest.json",
            "evidence.sqlite",
        }
    elif index in (1, 2):
        value = json_value(files["recertification.json"])
        by_sid = {row["principal"]: row for row in value["nested_paths"]}
        user = by_sid["S-1-5-21-100-200-300-1001"]
        if index == 1:
            assert user["state"] == "REPRESENTATIVE_PATH_CHANGED"
            assert user["after_path"] == [
                "S-1-5-32-544",
                "S-1-5-21-900-800-700-2001",
                "S-1-5-21-100-200-300-1001",
            ]
            assert by_sid["S-1-5-21-100-200-300-1002"]["state"] == "EXPOSURE_ADDED"
            assert (
                len(value["review_queue"]) == 2
                and value["current_audit"]["complete"] is True
            )
        else:
            assert user["state"] == "NOT_OBSERVED_UNVERIFIED"
            assert value["current_audit"]["complete"] is False
            assert len(value["current_audit"]["findings"]) == 2
    else:
        value = json_value(files["result.json"])
        assert len(value["changes"]) == 4


def exercise(window: Workbench, output: Path, reopen: bool) -> None:
    """Drive the same real widgets/mainloop/core with marked synthetic inputs; no arbitrary script, collector or API mock."""
    output.mkdir(mode=0o700)
    deadline = time.monotonic() + 55
    receipt: dict[str, Any] = {
        "schema": 1,
        "product": project.PRODUCT,
        "version": project.VERSION,
        **window.identity,
        "pid": os.getpid(),
        "parent_pid": os.getppid(),
        "synthetic": True,
        "reopen": reopen,
        "passed": False,
        "steps": [],
        "tcl_version": window.root.tk.call("info", "patchlevel"),
        "tk_version": window.root.tk.call("package", "require", "Tk"),
    }
    expected_runs = 6 if project.PRODUCT == "rmf-evidence-workbench" else 4

    def persist() -> None:
        """Write bounded aggregate identities/hashes only; no credentials or original private input paths."""
        (output / "acceptance.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
        )

    def finish(failed: bool = False) -> None:
        """Use ordinary Exit and retain exact original bundle identities for independent parent restart comparison."""
        receipt["passed"] = not failed
        window.acceptance_result = not failed
        receipt["bundles"] = {
            str(row["id"]): {
                name: hashlib.sha256(raw).hexdigest()
                for name, raw in window.state.files(row["id"]).items()
            }
            for row in window.state.history()
        }
        persist()
        window.exit()

    def checked(callback: Any) -> None:
        """A failed real oracle remains a failed receipt; no fallback, retry or reset is attempted."""
        try:
            callback()
        except Exception:
            receipt["failure_stage"] = callback.__name__
            finish(True)

    def wait(callback: Any) -> None:
        """Keep the real event loop responsive while this owned worker completes within its unchanged deadline."""
        if time.monotonic() > deadline:
            receipt["failure_stage"] = "owned-operation-deadline"
            finish(True)
        elif window.busy:
            window.root.after(60, lambda: wait(callback))
        else:
            checked(callback)

    def layout() -> None:
        """Real minimum-width layout keeps every lifecycle control fully visible even with long status text."""
        original = window.status.get()
        window.root.geometry("980x700")
        window.status.set(
            original
            + " Synthetic long-message layout check: existing evidence remains available and Exit waits for the owned operation."
        )
        window.root.update()
        receipt["layout"] = {
            "root": [window.root.winfo_width(), window.root.winfo_height()],
            "status": [
                window.status_label.winfo_width(),
                window.status_label.winfo_height(),
                window.status_label.winfo_reqheight(),
                int(window.status_label.cget("wraplength")),
            ],
            "buttons": {
                name: [
                    button.winfo_width(),
                    button.winfo_reqwidth(),
                    button.winfo_rootx() - window.root.winfo_rootx(),
                    button.winfo_rooty() - window.root.winfo_rooty(),
                    button.winfo_height(),
                ]
                for name, button in window.footer_buttons.items()
            },
        }
        assert (
            int(window.status_label.cget("wraplength"))
            <= window.status_label.winfo_width()
        )
        assert (
            window.status_label.winfo_height() >= window.status_label.winfo_reqheight()
        )
        for button in window.footer_buttons.values():
            assert button.winfo_width() >= button.winfo_reqwidth()
            assert button.winfo_rootx() >= window.root.winfo_rootx()
            assert (
                button.winfo_rootx() + button.winfo_width()
                <= window.root.winfo_rootx() + window.root.winfo_width()
            )
            assert (
                button.winfo_rooty() + button.winfo_height()
                <= window.root.winfo_rooty() + window.root.winfo_height()
            )
        window.status.set(original)
        window.root.geometry("1260x860")
        window.root.update()
        receipt["steps"].append(
            "real-minimum-width-long-status-all-lifecycle-controls-visible"
        )

    def rejected() -> None:
        """A mistaken user input must retain every previous bundle and report rejection instead of a new success."""
        assert len(window.state.history()) == expected_runs
        assert "rejected" in window.status.get().lower()
        receipt["steps"].append("actual-invalid-input-retains-original-history")
        finish()

    def export_and_reject() -> None:
        """The actual Export control writes exact selected evidence; the next bad input cannot replace it."""
        from unittest.mock import patch

        parent = output / "private-export"
        parent.mkdir()
        original = window.state.files(window.selected_run)
        with patch(
            "identitylab.desktop.filedialog.askdirectory", return_value=str(parent)
        ):
            window.export_button.invoke()
        target = next(parent.iterdir())
        assert {path.name: path.read_bytes() for path in target.iterdir()} == original
        receipt["steps"].append("actual-widget-exact-export")
        if project.PRODUCT == "rmf-evidence-workbench":
            window.values["tip"].set("0" * 64)
        else:
            window.mode.set(project.MODES[2])
            window.values["horizon"].set("169")
        window.authorized.set(True)
        window.run_button.invoke()
        wait(rejected)

    def completed(index: int) -> None:
        """Check actual persisted core results, choose literal findings/details and capture only owned synthetic pixels."""
        assert len(window.state.history()) == index + 1
        assert window.selected_run == index + 1
        files = window.state.files(index + 1)
        oracle(index, files)
        if index == 0:
            layout()
        if index in (0, 2):
            desired = (
                (
                    "Original evidence predicates"
                    if index == 0
                    else "Owner work calendar"
                )
                if project.PRODUCT == "rmf-evidence-workbench"
                else (
                    "Original identity findings"
                    if index == 0
                    else "Representative nested paths"
                )
            )
            window.view.set(desired)
            window.search.set("")
            window.render()
            assert window.table.get_children()
            window.table.selection_set("0")
            window.inspect()
            window.root.update()
            assert window.view.get() == desired and isinstance(
                json.loads(window.details.get("1.0", "end")), dict
            )
            capture(
                window,
                output
                / (
                    "selected-evidence.png"
                    if index == 0
                    else "owner-unknown-review.png"
                ),
            )
        receipt["steps"].append("actual-core-scenario-" + str(index + 1))
        if index + 1 == expected_runs:
            export_and_reject()
        else:
            start(index + 1)

    def start(index: int) -> None:
        """Prepared scenarios populate ordinary visible controls; explicit permission and actual Run remain mandatory."""
        window.prepared.set(project.SCENARIOS[index])
        window.load_prepared()
        assert not window.authorized.get()
        if index == 0:
            for field, source in (
                ("snapshot", "snapshot.json"),
                ("policy", "policy.json"),
            ):
                imported = output / ("selected-external-" + source)
                imported.write_bytes((project.ROOT / "examples" / source).read_bytes())
                window.values[field].set(str(imported))
            assert not window.authorized.get()
            receipt["steps"].append("actual-user-selected-external-snapshot-and-policy")
        window.authorized.set(True)
        window.run_button.invoke()
        wait(lambda: completed(index))

    def begin() -> None:
        """First launch starts empty; second process reopens the same real saved bundles without recalculation."""
        if reopen:
            assert len(window.state.history()) == expected_runs
            for identity in range(1, expected_runs + 1):
                window.history_table.selection_set(str(identity))
                window.open_button.invoke()
                assert window.selected_run == identity
                oracle(identity - 1, window.state.files(identity))
            receipt["steps"].append("actual-process-reopen-all-exact-bundles")
            finish()
        else:
            assert window.state.history() == []
            window.run_button.invoke()
            assert not window.busy and window.state.history() == []
            start(0)

    persist()
    checked(begin)
