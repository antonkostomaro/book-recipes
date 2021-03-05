import sqlite3
import time
import math


class FDataBase:
    def __init__(self):
        self.__db__ = db
        self.__cur = db.cursor()

    def getMenu(self):
        sql = """Select * FROM mainmenu"""
        try:
            self.__cur.execute(sql)
            res = self.__cur.fetchall()
            if res: return res

        except:
            print("Error")
            return []


        def addPost(self, title, text):
            try:
                tm = math.floor(time.time())
                self.__cur.execute("INSERT INTO posts VALUES(NULL, ?, ?, ?)",  (title, text, tm))
                self.__db.comit()

            except: sqlite3.Error as e:
            print('Ошибка добовление статьи' +str(e))
            return False

        return True


        def getPost(self, postId):
            try:

                self.__cur.execute(f"SELECT title, text FROM posts WHERE id = {postId} LIMIT 1")
                res =  self.__cur.fetchone()
                if res:
                    return res

            except: sqlite3.Error as e:
            print('Ошибка получения статьи' +str(e))

            return (False, False)

