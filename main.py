"""
HOLLOW PURPLE PLATFORM ENTRYPOINT
Enterprise Runtime Launcher
"""

import asyncio
import logging
import os
import sys
from dotenv import load_dotenv

from bootstrap.bootstrap import start_runtime


# ------------------------------------------------
# LOGGING SETUP
# ------------------------------------------------

def setup_logging():

    level = os.getenv("HP_LOG_LEVEL", "INFO")

    logging.basicConfig(
        level=level,
        format='{"time":"%(asctime)s","level":"%(levelname)s","service":"%(name)s","msg":"%(message)s"}'
    )


# ------------------------------------------------
# MAIN
# ------------------------------------------------

async def main():

    # Load environment variables
    load_dotenv("main.env")

    setup_logging()

    logger = logging.getLogger("hp.main")

    logger.info("Starting Hollow Purple Platform")

    try:

        runtime = await start_runtime()

        logger.info("Runtime initialized successfully")

        await runtime.run_forever()

    except Exception:

        logger.exception("Fatal platform failure")

        sys.exit(1)


# ------------------------------------------------
# PROGRAM START
# ------------------------------------------------

if __name__ == "__main__":

    asyncio.run(main())