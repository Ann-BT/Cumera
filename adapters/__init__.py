#!/usr/bin/env python3
"""
Vendor Adapter Package for QCVN 11 Cybersecurity Toolkit.
Provides camera-specific adapters for Axis OS (VAPIX), Oryza/Tiandy, and Generic ONVIF.
"""

from typing import Any, Dict, Optional

from adapters.base_adapter import BaseCameraAdapter
from adapters.axis_adapter import AxisCameraAdapter
from adapters.oryza_adapter import OryzaCameraAdapter
from adapters.generic_adapter import GenericCameraAdapter


def get_camera_adapter(config: Optional[Dict[str, Any]] = None) -> BaseCameraAdapter:
    """
    Factory to return the appropriate vendor camera adapter based on active profile or config metadata.
    - Axis profile / Axis vendor / Axis model -> AxisCameraAdapter
    - Oryza profile / Tiandy heritage / ORZ model -> OryzaCameraAdapter
    - Others -> GenericCameraAdapter
    """
    if config is None:
        try:
            from toolkit_config import load_config, get_active_profile
            config = load_config()
            profile_id = get_active_profile(config)
        except Exception:
            profile_id = ""
            config = {}
    else:
        profile_id = config.get("active_profile") or config.get("profile_id") or ""

    vendor = str(config.get("vendor") or config.get("target_camera", {}).get("vendor") or "").lower()
    model = str(config.get("model") or config.get("target_camera", {}).get("model") or "").lower()
    heritage = str(config.get("hardware_heritage") or "").lower()
    pid = str(profile_id).lower()

    if "axis" in pid or "axis" in vendor or "axis" in model:
        return AxisCameraAdapter(config)
    elif (
        "oryza" in pid
        or "oryza" in vendor
        or "oryza" in model
        or "tiandy" in pid
        or "tiandy" in vendor
        or "tiandy" in heritage
        or "orz" in pid
        or "orz" in model
    ):
        return OryzaCameraAdapter(config)
    else:
        return GenericCameraAdapter(config)


__all__ = [
    "BaseCameraAdapter",
    "AxisCameraAdapter",
    "OryzaCameraAdapter",
    "GenericCameraAdapter",
    "get_camera_adapter",
]
