from collections.abc import Sequence
from typing import Dict, Optional, Protocol

from textual.screen import ModalScreen

from wifang.models import ToolName
from wifang.persist.ap_state import DatedHashline
from wifang.ui.vault.modals.cpu_crack import CpuCrackConfigModal
from wifang.ui.vault.modals.hashcat import HashcatConfigModal
from wifang.ui.vault.modals.hashtopolis import HashtopolisConfigModal


class LaunchModalConstructor(Protocol):
    """The constructor every Vault tool's launch modal shares."""

    def __call__(self, confirm_label: str = "Launch", bssid: Optional[str] = None,
                 probed_ssids: Sequence[str] = (),
                 hashlines: Sequence[DatedHashline] = ()) -> ModalScreen[dict]: ...


UI_TOOLS: Dict[ToolName, LaunchModalConstructor] = {
    ToolName.HASHCAT: HashcatConfigModal,
    ToolName.CPU_CRACK: CpuCrackConfigModal,
    ToolName.HASHTOPOLIS: HashtopolisConfigModal,
}
