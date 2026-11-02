"""Join requests and invitations (lists and responses), and recommendations."""

from typing import Literal

from fastapi import APIRouter

from app import schemas
from app.deps import DB, CurrentUser
from app.serializers import recommendation_out, request_out
from app.services import groups as rules

router = APIRouter(tags=["requests"])


@router.get("/requests", response_model=list[schemas.JoinRequestOut])
def list_requests(direction: Literal["sent", "received"], db: DB, user: CurrentUser):
    return [request_out(r) for r in rules.list_requests(db, user, direction)]


@router.patch("/requests/{request_id}", response_model=schemas.JoinRequestOut)
def respond(request_id: str, payload: schemas.RespondIn, db: DB, user: CurrentUser):
    """accepted / declined (the receiver), withdrawn (the student who asked), cancelled (the Lead who invited)."""
    req = rules.respond_request(db, request_id, payload.status, user)
    db.commit()
    return request_out(req)


@router.get("/recommendations", response_model=list[schemas.RecommendationOut])
def list_recommendations(db: DB, user: CurrentUser, status: str = "all"):
    return [recommendation_out(r) for r in rules.list_recommendations(db, user, status)]


@router.post("/recommendations", response_model=schemas.RecommendationOut, status_code=201)
def create_recommendation(payload: schemas.RecommendationIn, db: DB, user: CurrentUser):
    rec = rules.create_recommendation(db, user, payload.groupId, payload.studentId, payload.note)
    db.commit()
    return recommendation_out(rec)


@router.post("/recommendations/{recommendation_id}/dismiss", response_model=schemas.RecommendationOut)
def dismiss(recommendation_id: str, db: DB, user: CurrentUser):
    rec = rules.dismiss_recommendation(db, recommendation_id, user)
    db.commit()
    return recommendation_out(rec)


@router.post("/recommendations/{recommendation_id}/invite", response_model=schemas.JoinRequestOut, status_code=201)
def invite(recommendation_id: str, payload: schemas.NoteIn, db: DB, user: CurrentUser):
    req = rules.invite_from_recommendation(db, recommendation_id, user, payload.note)
    db.commit()
    return request_out(req)
