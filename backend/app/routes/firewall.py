import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List
from ..security.auth import get_current_user
from ..services import firewall_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/firewall", tags=["Firewall"])


class ZoneRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    type: str = Field(default="custom")
    color: str = Field(default="#6b7280")
    description: str = Field(default="")
    cidrs: List[str] = Field(default_factory=list)
    default_policy: str = Field(default="deny")
    icon: str = Field(default="circle")


class InterZoneRuleRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    source_zone: str = Field(...)
    dest_zone: str = Field(...)
    protocol: str = Field(default="tcp")
    ports: List[int] = Field(default_factory=list)
    action: str = Field(default="block", pattern="^(block|allow)$")
    priority: int = Field(default=50, ge=0, le=100)
    description: str = Field(default="")


class ServiceRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    zone: str = Field(...)
    ip: str = Field(...)
    ports: List[int] = Field(default_factory=list)
    protocol: str = Field(default="tcp")
    icon: str = Field(default="server")


@router.get("/status")
def get_status(current_user=Depends(get_current_user)):
    return firewall_service.get_firewall_status()


@router.post("/enable")
def enable_firewall(current_user=Depends(get_current_user)):
    firewall_service.set_firewall_enabled(True)
    return {"status": "enabled"}


@router.post("/disable")
def disable_firewall(current_user=Depends(get_current_user)):
    firewall_service.set_firewall_enabled(False)
    return {"status": "disabled"}


@router.get("/zones")
def list_zones(current_user=Depends(get_current_user)):
    return {"zones": firewall_service.get_zones()}


@router.post("/zones")
def create_zone(req: ZoneRequest, current_user=Depends(get_current_user)):
    return {"zone": firewall_service.add_zone(req.model_dump())}


@router.put("/zones/{zone_id}")
def update_zone(zone_id: int, req: ZoneRequest, current_user=Depends(get_current_user)):
    zone = firewall_service.update_zone(zone_id, req.model_dump())
    if not zone:
        raise HTTPException(status_code=404, detail="Zone not found")
    return {"zone": zone}


@router.delete("/zones/{zone_id}")
def delete_zone(zone_id: int, current_user=Depends(get_current_user)):
    if not firewall_service.delete_zone(zone_id):
        raise HTTPException(status_code=404, detail="Zone not found")
    return {"status": "deleted"}


@router.post("/zones/{zone_id}/toggle")
def toggle_zone(zone_id: int, current_user=Depends(get_current_user)):
    zone = firewall_service.toggle_zone(zone_id)
    if not zone:
        raise HTTPException(status_code=404, detail="Zone not found")
    return {"zone": zone}


@router.get("/rules")
def list_rules(current_user=Depends(get_current_user)):
    return {"rules": firewall_service.get_inter_zone_rules()}


@router.post("/rules")
def create_rule(req: InterZoneRuleRequest, current_user=Depends(get_current_user)):
    return {"rule": firewall_service.add_inter_zone_rule(req.model_dump())}


@router.put("/rules/{rule_id}")
def update_rule(rule_id: int, req: InterZoneRuleRequest, current_user=Depends(get_current_user)):
    rule = firewall_service.update_inter_zone_rule(rule_id, req.model_dump())
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"rule": rule}


@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: int, current_user=Depends(get_current_user)):
    if not firewall_service.delete_inter_zone_rule(rule_id):
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"status": "deleted"}


@router.post("/rules/{rule_id}/toggle")
def toggle_rule(rule_id: int, current_user=Depends(get_current_user)):
    rule = firewall_service.toggle_inter_zone_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"rule": rule}


@router.get("/services")
def list_services(current_user=Depends(get_current_user)):
    return {"services": firewall_service.get_services()}


@router.post("/services")
def create_service(req: ServiceRequest, current_user=Depends(get_current_user)):
    return {"service": firewall_service.add_service(req.model_dump())}


@router.put("/services/{service_id}")
def update_service(service_id: int, req: ServiceRequest, current_user=Depends(get_current_user)):
    svc = firewall_service.update_service(service_id, req.model_dump())
    if not svc:
        raise HTTPException(status_code=404, detail="Service not found")
    return {"service": svc}


@router.delete("/services/{service_id}")
def delete_service(service_id: int, current_user=Depends(get_current_user)):
    if not firewall_service.delete_service(service_id):
        raise HTTPException(status_code=404, detail="Service not found")
    return {"status": "deleted"}


@router.get("/connections")
def get_connections(current_user=Depends(get_current_user)):
    return {"connections": firewall_service.get_active_connections()}


@router.get("/blocked-ips")
def get_blocked_ips(current_user=Depends(get_current_user)):
    return {"blocked_ips": firewall_service.get_blocked_ips()}


@router.post("/unblock-ip")
def unblock_ip(ip: str = Query(...), current_user=Depends(get_current_user)):
    if not firewall_service.unblock_ip(ip):
        raise HTTPException(status_code=404, detail="IP not found")
    return {"status": "unblocked", "ip": ip}


@router.get("/logs")
def get_logs(limit: int = Query(200, ge=1, le=5000), action: Optional[str] = Query(None), current_user=Depends(get_current_user)):
    return {"logs": firewall_service.get_connection_logs(limit, action), "total": len(firewall_service._connection_log)}


@router.post("/logs/clear")
def clear_logs(current_user=Depends(get_current_user)):
    firewall_service.clear_connection_log()
    return {"status": "cleared"}


@router.get("/traffic-matrix")
def get_traffic_matrix(current_user=Depends(get_current_user)):
    return {"matrix": firewall_service.get_zone_traffic_matrix()}


@router.get("/zone-connections/{zone_name}")
def get_zone_connections(zone_name: str, current_user=Depends(get_current_user)):
    return {"connections": firewall_service.get_zone_connections(zone_name)}


@router.get("/check")
def check_connection(remote_ip: str = Query(...), remote_port: int = Query(...), local_ip: str = Query("127.0.0.1"), local_port: int = Query(0), protocol: str = Query("tcp"), current_user=Depends(get_current_user)):
    return firewall_service.check_connection(remote_ip, remote_port, local_ip, local_port, protocol)
