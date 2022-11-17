import sqlite3
from datetime import datetime


class PrjDataBase:
    def __init__(self, name):
        self.conn = sqlite3.connect(name)

    # create clients and files databases
    def create_and_open(self):
        try:
            sql_create_clients_table = """ CREATE TABLE IF NOT EXISTS clients (
                                                ID text PRIMARY KEY,
                                                Name text NOT NULL,
                                                Public_key text,
                                                Last_seen text,
                                                AES_key text
                                            );"""
            sql_create_files_table = """ CREATE TABLE IF NOT EXISTS files (
                                                    ID text NOT NULL,
                                                    File_Name text NOT NULL,
                                                    Path_name text,
                                                    Verified integer
                                                );"""
            self.conn.execute(sql_create_clients_table)
            self.conn.execute(sql_create_files_table)
            self.conn.commit()
            print("[+] Connected to data base.")
            return 1
        except Exception as e:
            print("[-] Can't connect to data base or create tables.\n" + str(e))
            return 0

    # print data bases
    def print_db(self):
        # Creating a cursor object using the cursor() method
        cursor = self.conn.cursor()

        # clients
        print('\nData in clients table:')
        data = cursor.execute('''SELECT * FROM clients''')
        for row in data:
            print(row)

        # files
        print('\nData in files files:')
        data = cursor.execute('''SELECT * FROM files''')
        for row in data:
            print(row)

        # Commit your changes in the database
        self.conn.commit()

    # get username, check if the name already exist in database
    def check_if_user_name_exist(self, name: str):
        sql_search_user_name_query = "SELECT * FROM clients WHERE Name = ?"
        cur = self.conn.cursor()
        cur.execute(sql_search_user_name_query, (name,))
        results = cur.fetchall()
        self.conn.commit()
        return len(results)

    # get file name, check if the file already exist in database
    def check_if_file_name_exist(self, name: str):
        sql_search_user_name_query = "SELECT * FROM files WHERE File_Name = ?"
        cur = self.conn.cursor()
        cur.execute(sql_search_user_name_query, (name,))
        results = cur.fetchall()
        self.conn.commit()
        return len(results)

    # add user to users database
    def add_user(self, name, user_id):
        add_user_query = "INSERT INTO clients VALUES (?,?,?,?,?)"
        self.conn.execute(add_user_query, (user_id, name, "", str(datetime.utcnow()), ""))
        self.conn.commit()

    # set the public key of user
    def set_keys(self, client_id, pub_key, aes_key):
        curser = self.conn.cursor()
        update_query = '''UPDATE clients SET Public_key = ?, Last_seen = ?, AES_key = ? WHERE ID = ?'''
        curser.execute(update_query, (pub_key, str(datetime.utcnow()), aes_key, client_id))
        self.conn.commit()

    # add file info to files database
    def add_file(self, user_id, file_name, path):
        # if file not exist in database -> add the file, otherwise update file data (overriding)
        if self.check_if_file_name_exist(file_name) == 0:
            add_user_query = "INSERT INTO files VALUES (?,?,?,?)"
            self.conn.execute(add_user_query, (user_id, file_name, path, 0))
            self.conn.commit()
        else:
            curser = self.conn.cursor()
            update_query = '''UPDATE files SET ID = ?, Path_name = ?  WHERE File_Name = ?'''
            curser.execute(update_query, (user_id, path, file_name))
            self.conn.commit()

    # update file data with verified value to true
    def set_verified_file(self, file_name):
        curser = self.conn.cursor()
        update_query = '''UPDATE files SET Verified = ? WHERE File_Name = ?'''
        curser.execute(update_query, (1, file_name))
        self.conn.commit()

    # close db connection
    def close(self):
        self.conn.close()

    # delete users db
    def delete_users(self):
        self.conn.execute("DELETE FROM clients")
        self.conn.commit()

    # delete files db
    def delete_files(self):
        self.conn.execute("DELETE FROM files")
        self.conn.commit()



