"""TKIP Michael-MIC injection attack."""
from wifit3.campaigns.tkip.campaign import TkipInject
from wifit3.campaigns.tkip.precheck import Verdict, assess

__all__ = ["Verdict", "assess", "TkipInject"]
