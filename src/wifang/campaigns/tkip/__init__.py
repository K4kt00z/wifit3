"""TKIP Michael-MIC injection attack."""
from wifang.campaigns.tkip.campaign import TkipInject
from wifang.campaigns.tkip.precheck import Verdict, assess

__all__ = ["Verdict", "assess", "TkipInject"]
