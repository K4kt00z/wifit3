"""WEP attack suite (fake-auth, ARP replay, ChopChop, PTW crack).

The orchestrator ``WepCampaign`` lives in ``campaign.py``; it is re-exported here
so callers use ``from wifang.campaigns.wep import WepCampaign``.
"""
from wifang.campaigns.wep.campaign import WepCampaign

__all__ = ["WepCampaign"]
