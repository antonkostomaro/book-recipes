from celery import Celery
from selenium import webdriver
from start import Post, db
from datetime import datetime, timedelta
from celery.schedules import crontab
app = Celery('add', broker='pyamqp://guest@localhost//')


@app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    sender.add_periodic_task(
        crontab(hour=7, minute=30, day_of_week=1),
        add.s('Happy Mondays!'),
    )
@app.task
def add():
    options = webdriver.ChromeOptions()
    options.add_argument("user-agent=Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0")
    options.headless = True

    driver = webdriver.Chrome()
    j = str("https://www.russianfood.com/recipes/recipe.php?rid=")
    g = []
    listNamesAll = []
    listAuthorsAll = []
    ma = []

    try:
        for i in range(1599, 1608, 3):
            t = j + str(i)
            g.append(t)

        for q in g:
            driver.get(q)
            listNames = driver.find_elements_by_id('how')
            listAuthors = driver.find_elements_by_xpath(
                '//*[@id="print"]')
            for element in listAuthors:
                listAuthorsAll.append(element.text)
            for dd in listNames:
                listNamesAll.append(dd.text)

        for element in listAuthorsAll:
            ma.append(element)
        import time
        while listNamesAll and ma:
            d = listNamesAll.pop(0)
            b = ma.pop(0)
            time.sleep(3)
            now = datetime.utcnow()
            p1 = Post(title=b, content=d, user_id=1, date_posted=now + timedelta(seconds=1))
            db.session.add(p1)
            db.session.commit()
    except :

        driver.close()
add()