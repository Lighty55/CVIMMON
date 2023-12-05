#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" This module checks the validity of the operations if they are allowed
based on the last entires on the SQLITE DB
"""

import argparse
from argparse import RawTextHelpFormatter
import datetime
import os
import sys

from database import constants as cv # constants_variables
from database import database as DB # Class
if __name__ == "__main__":
    sys.path.insert(1, os.getcwd())
    import utils.logger as logger

LOG_DIR = "/var/log/cvimmonha/"
STEP_1 = '1'
STEP_7 = '7'

# The following dict specifies the allowed operations after failed operations
# The key is the failed operation and the value is the operation
# allowed if we encounter the failed operation(key)
# Operations not in the dict key are considered non-blocking
# None means no operation is allowed
ALLOWED_OPERATION = {cv.OP_ADD_MASTER: cv.OP_REMOVE_WORKER,
                     cv.OP_REPLACE_MASTER: cv.OP_REPLACE_MASTER,
                     cv.OP_REMOVE_WORKER: cv.OP_REMOVE_WORKER,
                     cv.OP_RECONFIGURE: None,
                     cv.OP_UPDATE: None,
                     cv.OP_ROLLBACK: None
                    }

class ValidateOperation():
    """ If installation fails on any step except 1( Validation) -> No operation
    allowed. The blocked operations confer to the dictionary defined above
    """

    def __init__(self, db, log):
        self.dbase = db
        self.log = log

    def is_operation_allowed(self, operation):
        """Input: operation name
        This function checks for the validity of an operation.

        operation: all operations including install operations steps
                   step 1 can never be passed

        This method is called right before the orchestrator is started.
        If any operation runs multiple steps of the orchestrator, this function is
        called at each step

        Returns bool
        """

        # Format: Attributes of last_operation => op_name, status, timestamp
        last_operation = self.dbase.get_last_operation_entry()
        last_install = self.dbase.get_last_install_entry()

        # Non install operations are only allowed after a successful install to step 7
        if operation != cv.OP_INSTALL:
            if last_install.status != cv.STATUS_SUCCESS or \
               last_install.op_name.split('__')[2] != STEP_7:
                print("Operation %s is not allowed until a full installation is completed"\
                      % (operation))
                self.log.error("Validate Operation: operation %s is not allowed "
                               "until a full installation is completed"
                               % (operation))
                return False

        # Verify that after a successful update we can only do rollback or commit
        # Note that successful update last operation means that
        # there must be a full successful install
        if last_operation.op_name.split('__')[0] == cv.OP_UPDATE and \
           last_operation.status == cv.STATUS_SUCCESS:
            # Format: (str) last_operation.op_name -> update__step__7
            if last_operation.op_name.split('__')[2] == STEP_7:
                # If last operation was successful update, force user to commit or rollback
                if not operation in (cv.OP_ROLLBACK, cv.OP_COMMIT):
                    print("POD has been updated successfully. "
                          "And requires a Commit or Rollback before performing any operations.")
                    self.log.error("Validate Operation: POD has been updated successfully. "
                                   "And requires a Commit or Rollback "
                                   "before performing any operations.")
                    return False

        # Verify that commit and rollback can only be done
        # if the last operation was a successful update
        if operation in (cv.OP_ROLLBACK, cv.OP_COMMIT):
            # verify that we have an update successful.
            if last_operation.op_name.split('__')[0] != cv.OP_UPDATE or \
               last_operation.status != cv.STATUS_SUCCESS:
                if last_operation.op_name.split('__')[2] == STEP_7:
                    print("Cannot commit or rollback without a previous successful update")
                    self.log.error("Validate Operation: Cannot commit or rollback"
                                   " without a previous successful update")
                    return False

        if last_install.status == cv.STATUS_SUCCESS:
            # Verify non-install operation can only be done after a full install succeeded (step 7)
            if last_install.op_name.split('__')[2] != STEP_7:
                if operation != cv.OP_INSTALL:
                    print("Operation %s is not allowed until "
                          "a full installation is completed" % (operation))
                    self.log.info("Validate Operation: : Operation %s is not allowed "
                                  "until a full installation is completed"
                                  % (operation))
                    return False
        elif last_install.status == cv.INITIAL_STATUS:
            # Following validate_operations.py -r
            if operation != cv.OP_INSTALL:
                print("Operation %s is not allowed until a full installation is completed"\
                      % (operation))
                self.log.info("Validate Operation: Operation %s is not allowed until "
                              "a full installation is completed" % (operation))
                return False
        else:
            # installation is in failed state
            self.log.error("Validate Operation: Last install : {}:{}. Can't proceed further.".\
                            format(last_install.op_name, last_install.status))
            print("The last install was not successful. "\
                    "Please Unbootstrap and Reinstall again")
            return False

        # Fully installed
        # Last operation failed
        # Only certain operations are allowed based on what operation failed
        # (ALLOWED_OPERATION dict)
        if last_operation.status != cv.STATUS_SUCCESS:
            self.log.info("Validate Operation: Last operation: {}:{}".\
                          format(last_operation.op_name, last_operation.status))
            failed_operation = last_operation.op_name
            failed_step = None
            if "step" in last_operation.op_name.split('__'):
                failed_operation = last_operation.op_name.split('__')[0]
                failed_step = last_operation.op_name.split('__')[2]
            if failed_operation in ALLOWED_OPERATION.keys():
                self.log.info("Validate Operation: Last failed operation {} "\
                                .format(failed_operation))
                allowed_operation = ALLOWED_OPERATION[failed_operation]
                if allowed_operation != operation:
                    self.log.error("Validate Operation: The operation {} is not allowed "
                                   "after failed operation {} The allowed operations are: {}"\
                                   .format(operation, failed_operation, allowed_operation))
                    print("Last Operation {} was failed. After failing {}, "
                          "the allowed operations are: {}"\
                          .format(failed_operation, failed_operation, allowed_operation))
                    return False
        self.log.info("Validate Operation: Validation passed. Continuing with {}"\
            .format(operation))
        return True

    def is_last_operation_running(self):
        """ Checks for running status in the last entries of the DB.
        Returns: True(bool) is any of them has entry running
        """

        return (self.dbase.get_last_operation_entry().status == cv.STATUS_RUNNING) \
            or (self.dbase.get_last_install_entry().status == cv.STATUS_RUNNING)

    def is_full_installation_allowed(self):
        """ Check if full installation is allowed
        Full Installation is allowed only when one of the fllowing condtions are met
        Table exists and:
            Last install status is not success
            Last install status is success and last install op is not install__step__7
            Last install op is INITIAL_OP (operation__step__0)
        Returns: bool (True if full installation is allowed, else False)
        """

        last_install_entry = self.dbase.get_last_install_entry()
        if self.dbase.does_install_table_exist() and\
                (last_install_entry.status != cv.STATUS_SUCCESS or\
                (last_install_entry.status == cv.STATUS_SUCCESS and\
                    last_install_entry.op_name != cv.FULL_INSTALL_STEP_7) or\
                        last_install_entry.op_name == cv.INITIAL_OP):
            return True
        return False

def main(reset_db=False, all_success=False, num_entries=10):
    """ Intended for developers use
    Helps to override the SQLITE DB entries and override the
    failed/blocked operations
    """

    # Create a logger here
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S_%f')
    log_dir_ts = LOG_DIR + timestamp
    logger.set_log_dir(log_dir_ts)
    logger_inst = logger.Logger(name="Runner", level="debug")
    log = logger_inst.get_logger()
    log.debug("Start Validate Operation as main...")

    database = DB.Database(cv.SQLITE_DB_PATH, log)

    if reset_db:
        database.insert_install_entry(cv.INITIAL_OP, cv.INITIAL_STATUS, cv.INITIAL_TS)
        database.insert_operation_entry(cv.INITIAL_OP, cv.INITIAL_STATUS, cv.INITIAL_TS)
    if all_success:
        database.insert_install_entry(cv.FULL_INSTALL_STEP_7, cv.STATUS_SUCCESS,
                                      cv.INITIAL_TS)
        database.insert_operation_entry(cv.INITIAL_OP, cv.STATUS_SUCCESS, cv.INITIAL_TS)
    if num_entries:
        install_cmd = "SELECT * FROM install ORDER BY id DESC LIMIT {}" \
                      .format(str(num_entries))
        database.cur.execute(install_cmd)
        print("Last {} install entries are: ".format(num_entries))
        for elem in database.cur.fetchall():
            print(elem)
        print("\n##################################################\n")
        operation_cmd = "SELECT * FROM operation ORDER BY id DESC LIMIT {}" \
                        .format(str(num_entries))
        database.cur.execute(operation_cmd)
        print("Last {} operation entries are: ".format(num_entries))
        for elem in database.cur.fetchall():
            print(elem)


    database.conn.close()

if __name__ == "__main__":
    PARSER = argparse.ArgumentParser(description="Validate Operations:\n\
                                This tool helps override the failed operation.\
                                Intended for internal use.",
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument("-r", "--reset-db", action='store_true', dest="reset_db",
                        help="This argument will reset the db but will still \
                              retain past entries")
    PARSER.add_argument("-s", "--all-success", action='store_true',
                        dest="all_success",
                        help="This will set last entry as success in all the tables")
    PARSER.add_argument(
        '-l', '--list-last-entries', dest="num_entries", type=int,
        help='This will list last entries in both install and operation table in \
        the database', action='store')
    OPTIONS = PARSER.parse_args()
    main(OPTIONS.reset_db, OPTIONS.all_success, OPTIONS.num_entries)
