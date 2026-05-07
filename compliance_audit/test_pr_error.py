# test_pr_errors.py

import os

import json

import requests

import subprocess

import hashlib
 
# ── Hardcoded secrets ─────────────────────────────────────────────────────────

DB_PASSWORD = "admin123"

API_KEY = "sk-prod-xK9mN2pL8qR5vT1wY4zA7cB0dE3fG6hJ"

AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

DB_URL = "mongodb://admin:password123@prod-db.company.com:27017/users"
 
 
class UserProcessor:
 
    def __init__(self):

        self.db = DB_URL

        self.cache = {}
 
    # ── SQL injection ─────────────────────────────────────────────────────────

    def get_user(self, user_id):

        query = "SELECT * FROM users WHERE id = " + str(user_id)

        return requests.get(f"http://internal-api/query?q={query}", verify=False)
 
    # ── Unsafe eval ───────────────────────────────────────────────────────────

    def load_config(self, config_str):

        return eval(config_str)
 
    # ── OS command injection ──────────────────────────────────────────────────

    def run_report(self, filename):

        os.system(f"cat {filename}")

        subprocess.call(f"rm -rf {filename}", shell=True)
 
    # ── Bare except, no error handling ────────────────────────────────────────

    def process_batch(self, items):

        results = []

        for item in items:

            try:

                results.append(self.process_item(item))

            except:

                pass

        return results
 
    # ── No None handling ──────────────────────────────────────────────────────

    def process_item(self, item):

        return item["data"]["value"].strip().upper()
 
    # ── O(n²) nested loop ─────────────────────────────────────────────────────

    def find_duplicates(self, users):

        duplicates = []

        for i in range(len(users)):

            for j in range(len(users)):

                if i != j and users[i]["email"] == users[j]["email"]:

                    duplicates.append(users[i])

        return duplicates
 
    # ── Loading entire collection into memory ─────────────────────────────────

    def get_all_users(self):

        all_users = list(requests.get("http://internal-api/users").json())

        return [u for u in all_users if u["active"]]
 
    # ── Magic numbers ─────────────────────────────────────────────────────────

    def calculate_score(self, user):

        if user["age"] > 25:

            score = user["points"] * 0.85

            if score > 1000:

                return score - 42

        return user["points"] * 0.60
 
    # ── Dead code ─────────────────────────────────────────────────────────────

    def _old_process(self, data):

        result = []

        for d in data:

            result.append(d)

        return result
 
    # ── Critical function with no tests ───────────────────────────────────────

    def transfer_funds(self, from_account, to_account, amount):

        if amount <= 0:

            return False

        from_balance = self.get_balance(from_account)

        self.update_balance(from_account, from_balance - amount)

        self.update_balance(to_account, self.get_balance(to_account) + amount)

        return True
 
  