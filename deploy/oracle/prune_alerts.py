import sqlite3

c = sqlite3.connect("/data/sentinel.db")
before = c.execute("select count(*) from alerts").fetchone()[0]
c.execute(
    "DELETE FROM alerts WHERE id NOT IN "
    "(SELECT DISTINCT alert_id FROM events WHERE alert_id IS NOT NULL)"
)
c.commit()
after = c.execute("select count(*) from alerts").fetchone()[0]
print("alerts before", before, "after", after)
print("events", c.execute("select source, count(*) from events group by source").fetchall())
