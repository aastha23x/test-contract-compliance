from pymongo import MongoClient
from pprint import pprint

client = MongoClient("mongodb://localhost:27017/")
db = client["jira_audit_db"]

collections = ["access_logs", "audit_evidence", "cloud_audit", "db_activity", "deployments"]

for col_name in collections:
    col = db[col_name]
    count = col.count_documents({})
    
    print("=" * 60)
    print(f"COLLECTION: {col_name.upper()}")
    print(f"Total documents: {count}")
    print("-" * 60)
    
    if count == 0:
        print("No data found in this collection")
    else:
        print("Sample record:")
        pprint(col.find_one({}))
    
    print()

print("=" * 60)
print("MongoDB check complete!")
client.close()
