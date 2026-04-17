from supervisor_api import evidence
from supervisor_api.db import Base, SessionLocal, engine
from supervisor_api.models import Action


def test_chain_builds_and_verifies():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        action = Action(action_type="refund", status="received", payload={"amount": 10})
        db.add(action)
        db.flush()

        e1 = evidence.append(db, action_id=action.id, event_type="action.received", payload={"n": 1})
        e2 = evidence.append(db, action_id=action.id, event_type="decision.made", payload={"n": 2})
        e3 = evidence.append(db, action_id=action.id, event_type="review.resolved", payload={"n": 3})
        db.commit()

        assert e1.seq == 1 and e2.seq == 2 and e3.seq == 3
        assert e2.prev_hash == e1.hash
        assert e3.prev_hash == e2.hash

        ok, broken = evidence.verify(db, action.id)
        assert ok is True
        assert broken is None
    finally:
        db.close()


def test_tampered_payload_breaks_chain():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        action = Action(action_type="refund", status="received", payload={"amount": 10})
        db.add(action)
        db.flush()

        e1 = evidence.append(db, action_id=action.id, event_type="action.received", payload={"n": 1})
        e2 = evidence.append(db, action_id=action.id, event_type="decision.made", payload={"n": 2})
        db.commit()

        # Tamper: mutate payload of event 2 without recomputing hash.
        e2.event_payload = {"n": 2, "tampered": True}
        db.add(e2)
        db.commit()

        ok, broken = evidence.verify(db, action.id)
        assert ok is False
        assert broken == e2.seq
        _ = e1  # silence unused
    finally:
        db.close()
