import base64
from typing import Tuple
import logging
from time import sleep

from rich.live import Live

from src.pad_tickler.ui import ui


POC_ARGS = {
  "payload": {
    "plaintext": "Hello, world!",
    "alg": "AES-128-CBC",
    "iv_b64": "L4GNQGz48epdIiVCc2MboQ==",
    "ciphertext_b64": "mrH+LB63tYaVm7ZG3uFoaw=="
  },
  "target": {
      "origin": "http://localhost:8000",
      "method": "POST",
      "path": "/api/validate",
      "headers": {
        "Content-Type": "application/json"
      },
      "variable_name": "ciphertext_b64",
      "variable_location": "body",
  }
}


logger = logging.getLogger("main")
logger.setLevel(logging.INFO)
logger.addHandler(ui.get_ui_log_handler())


def load_bytes() -> Tuple[bytearray, bytearray]:
    ciphertext = bytearray(base64.b64decode(POC_ARGS["payload"]["ciphertext_b64"]))
    iv = bytearray(base64.b64decode(POC_ARGS["payload"]["iv_b64"]))
    return ciphertext, iv


def main():
    try:
        # Highest level UI components
        console = ui.get_console()
        layout, progress = ui.get_layout(console)

        # Live loop
        with Live(layout, console=console, screen=True, transient=False, auto_refresh=False, refresh_per_second=8) as live:

            # Tasks
            t1 = progress.add_task("Current batch", total=50)
            t2 = progress.add_task("Full dataset", total=2000)

            ciphertext, iv = load_bytes()
            logger.info(f"Loaded bytes: len(ciphertext)={len(ciphertext)}, len(iv)={len(iv)}")

            for i in range(2000):
                if not progress.tasks[t1].finished:
                    progress.advance(t1, 1)
                progress.advance(t2, 1)

                # Re-render the bottom pane with the newest N lines.
                LOG_LINES_VISIBLE = layout["lower"].size - 2
                layout["lower"].update(ui.render_log_panel("Logs", LOG_LINES_VISIBLE))

                live.refresh()
                sleep(0.03)

    except KeyboardInterrupt:
        print("Exiting program....")

    finally:
        # Paint screen one last time on exit to preserve.
        console.clear()
        console.print(layout, height=console.size.height, crop=True)

if __name__ == "__main__":
    main()
