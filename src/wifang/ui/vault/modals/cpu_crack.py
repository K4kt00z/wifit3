from textual.app import ComposeResult

from wifang.persist.config import Config, CpuCrackSettings
from wifang.ui.vault.modals.wordlists import WordlistConfigModal


class CpuCrackConfigModal(WordlistConfigModal):
    """Configuration modal for CPU Crack jobs."""

    dialog_title = "CPU Crack"

    def _settings(self) -> CpuCrackSettings:
        return Config.cpu_crack

    def _compose_fields(self) -> ComposeResult:
        yield from self._compose_wordlists()
        yield from self._compose_password_sources()
