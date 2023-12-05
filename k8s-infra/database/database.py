#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Manage Database for tracking operation status and timeline.

This Module has the class that handles the database for monitoring the
status/ timestamp of the operations being performed by k8s-runner
"""

import sqlite3
import os.path
import datetime
import json

from constants import INITIAL_OP
from constants import INITIAL_TS
from constants import INITIAL_STATUS
from constants import FULL_INSTALL_STEP_7
from constants import STATUS_SUCCESS
from constants import STATUS_FAIL
# Max No. of entries stored in a db
DEFAULT_MAX_ENTRIES = 1000
STATUS_FILE = "/opt/cisco/k8s_status.json"

class DbEntry():
    """This class stores details of a single database entry"""
    def __init__(self, entry_tuple):
        self.id = entry_tuple[0]
        self.op_name = entry_tuple[1]
        self.status = entry_tuple[2]
        self.timestamp = entry_tuple[3]

class Database():
    """This Class handles the SQLITE DB which monitors the history of operations
    performed and stores the details about it success, failure.
    """

    def __init__(self, db_path, log, max_entries=DEFAULT_MAX_ENTRIES):
        self.log = log
        self.max_entries = max_entries
        # Check for the dir
        if not os.path.isdir(os.path.dirname(db_path)):
            self.log.info("Directory {} doesn't exist, creating".format(os.path.dirname(db_path)))
            os.makedirs(os.path.dirname(db_path))

        self.conn = sqlite3.connect(db_path)
        self.cur = self.conn.cursor()

        # Check if operation table exists. Else create one
        self.cur.execute\
            ("SELECT count(name) FROM sqlite_master WHERE type='table' AND name= 'operation'")
        if self.cur.fetchone()[0] == 1:
            self.log.info('SQLITE operation Table exists.')
        else:
            self.log.info("SQLITE DB: The operation table doesn't exist")
            try:
                self.cur.execute(" CREATE TABLE  operation ( ID INTEGER PRIMARY KEY AUTOINCREMENT,\
                                operation text, status text, timestamp text )")
                # In case the DB does not exist, check for a STATUS_FILE, which
                # is included in pre-DB releases as well
                last_op = self.get_last_operation_from_file()
                if last_op:
                    if last_op['status'] == 'Success':
                        self.insert_operation_entry(last_op['operation_name'],
                                                    STATUS_SUCCESS, INITIAL_TS)
                    else:
                        self.insert_operation_entry(last_op['operation_name'],
                                                    STATUS_FAIL, INITIAL_TS)
                else:
                    self.insert_operation_entry(INITIAL_OP, INITIAL_STATUS, INITIAL_TS)
            except:
                self.log.info("Cannot Create operation table...")
                raise sqlite3.DatabaseError

        # Check if install table exists. Else create one
        self.cur.execute\
            ("SELECT count(name) FROM sqlite_master WHERE type='table' AND name= 'install'")
        if self.cur.fetchone()[0] == 1:
            self.log.info('SQLITE install Table exists.')
        else:
            self.log.info("SQLITE DB: The install table doesn't exist")
            try:
                self.cur.execute(" CREATE TABLE  install ( ID INTEGER PRIMARY KEY AUTOINCREMENT,\
                                operation text, status text, timestamp text )")
                # In case the DB does not exist, check for a STATUS_FILE, which
                # is included in pre-DB releases as well
                last_op = self.get_last_operation_from_file()
                if last_op:
                    if last_op['status'] == 'Success':
                        self.insert_install_entry(last_op['operation_name'],
                                                  STATUS_SUCCESS, INITIAL_TS)
                    else:
                        self.insert_install_entry(last_op['operation_name'],
                                                  STATUS_FAIL, INITIAL_TS)
                else:
                    self.insert_install_entry(INITIAL_OP, INITIAL_STATUS, INITIAL_TS)
            except:
                self.log.info("Cannot Create install table...")
                raise sqlite3.DatabaseError

    def does_install_table_exist(self):
        """ Checks if the install table exists.
        Returns: (bool)
        """

        self.cur.execute(" SELECT count(name) FROM sqlite_master WHERE\
                            type='table' AND name= 'install' ")
        if self.cur.fetchone()[0] == 1:
            return True
        return False

    def does_operation_table_exist(self):
        """ Checks if the operation table exists.
        Returns: (bool)
        """

        self.cur.execute(" SELECT count(name) FROM sqlite_master WHERE\
                            type='table' AND name= 'operation' ")
        if self.cur.fetchone()[0] == 1:
            return True
        return False

    def insert_install_entry(self, operation, status, timestamp=None):
        """ Dumps an entry in the install table """
        if not timestamp:
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S_%f')
        # Check for number of entries, if more than MAX_ENTRIES => delete all of them
        self.cur.execute('SELECT COUNT(*) FROM install')
        if self.cur.fetchone()[0] >= self.max_entries:
            self.cur.execute('DELETE FROM install WHERE id IN \
                              (SELECT id FROM install ORDER BY id ASC LIMIT 1)')
        if 'step' not in operation.split("__"):
            operation = operation + ("__step__0")
        db_entry = {'timestamp': timestamp, "install": status, 'operation': operation}
        self.cur.execute("INSERT INTO install (operation, status, timestamp) VALUES \
                    (:operation, :install, :timestamp)", db_entry)
        self.conn.commit()

    def insert_operation_entry(self, operation=INITIAL_OP, status=None, timestamp=None):
        """ Dumps an entry in the operation table """
        if not timestamp:
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S_%f')
        self.cur.execute('SELECT COUNT(*) FROM operation')
        if self.cur.fetchone()[0] >= self.max_entries:
            self.cur.execute('DELETE FROM operation WHERE id IN \
                             (SELECT id FROM operation ORDER BY id ASC LIMIT 1)')
        if 'step' not in operation.split("__"):
            operation = operation + ("__step__0")
        db_entry = {'operation': operation, 'timestamp': timestamp, "status": status}
        self.cur.execute("INSERT INTO operation (operation, status, timestamp) VALUES \
                    (:operation, :status, :timestamp)", db_entry)
        self.conn.commit()

    def get_last_install_entry(self):
        """ Returns an instance of class DbEntry of last entry in the install table """
        self.cur.execute("SELECT * FROM install ORDER BY id DESC LIMIT 1")
        db_entry = DbEntry(self.cur.fetchone())
        return db_entry

    def get_last_operation_entry(self):
        """ Returns an instance of class DbEntry of last entry in the operation table """
        self.cur.execute("SELECT * FROM operation ORDER BY id DESC LIMIT 1")
        db_entry = DbEntry(self.cur.fetchone())
        return db_entry

    def get_last_operation_from_file(self):
        """ Returns a last operation name from SETUP_FILE """
        try:
            with open(STATUS_FILE) as f:
                k8s_status = json.load(f)
                return k8s_status
        except (OSError, IOError) as e:
            return None

    def get_operations_count(self):
        """ Returns the number of entries in operation table of DB """
        self.cur.execute('SELECT COUNT(*) FROM operation')
        return self.cur.fetchone()[0]

    def get_install_count(self):
        """ Returns the number of entries in install table of DB """
        self.cur.execute('SELECT COUNT(*) FROM install')
        return self.cur.fetchone()[0]
