import sqlite3

c = sqlite3.connect("/data/sentinel.db")
print("before events", c.execute("select source, count(*) from events group by source").fetchall())
print("before alerts", c.execute("select source, count(*) from alerts group by source").fetchall())
c.execute("DELETE FROM events WHERE source = 'simulator'")
c.execute("DELETE FROM alerts WHERE source IN ('simulator', 'mixed')")
c.execute("DELETE FROM campaigns")
c.execute("DELETE FROM ip_counts")
c.commit()
print("after events", c.execute("select source, count(*) from events group by source").fetchall())
print("after alerts", c.execute("select source, count(*) from alerts group by source").fetchall())
print("remaining events", c.execute("select count(*) from events").fetchone()[0])
