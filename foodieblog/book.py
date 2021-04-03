import unittest
from datetime import datetime, timedelta
from start import *
class TestCase(unittest.TestCase):

    def test_follow(self):

        u3 = User(username='mary', email='mary@example.com', password='2222')
        u4 = User(username='david', email='david@example.com', password='42323')

        db.session.add(u3)
        db.session.add(u4)
        # make four posts
        utcnow = datetime.utcnow()

        p3 = Post(title="post from mary", author=u3, date_posted=utcnow + timedelta(seconds=3))
        p4 = Post(title="post from david", author=u4, date_posted=utcnow + timedelta(seconds=4))

        db.session.add(p3)
        db.session.add(p4)
        db.session.commit()
        # setup the followers

        u3.follow(u3)  # mary follows herself
        u3.follow(u4)  # mary follows david
        u4.follow(u4)  # david follows himself


        db.session.add(u3)
        db.session.add(u4)
        db.session.commit()
        # check the followed posts of each user

        f3 = u3.followed_posts().all()
        f4 = u4.followed_posts().all()

        assert len(f3) == 2
        assert len(f4) == 1

        assert f3 == [p4, p3]
        assert f4 == [p4]

if __name__ == '__main__':
    unittest.main()