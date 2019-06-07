import mysql.connector
from mysql.connector import Error
import pandas as pd
from mysql.connector import errorcode
import sqlalchemy
import mysql.connector

def insert(filename):
    route="~/Desktop/upload/"
    database_username = 'root'
    database_password = 'Thisis@rootuser2'
    database_ip       = '127.0.0.1'
    database_name     = 'vc'
    mysql_charset='utf8mb4'
    database_connection = sqlalchemy.create_engine('mysql+mysqlconnector://{0}:{1}@{2}/{3}?charset=utf8'.
                                               format(database_username, database_password, 
                                                      database_ip, database_name, charset='utf8'), pool_recycle=1, pool_timeout=57600,encoding='utf8').connect()
    df = pd.read_excel(route+filename, 'Vulnerability Tracker', skiprows=2)
    df=df.drop(['Overdue Date','Resolution Recommendations', 'Vulnerability Issue and Impact', 'APPL ID','Target Resolution Date ' ], axis=1)
    print(df)
    df = df.rename(columns={'Impact of Exploit\n(1 - 5)': 'Impact of Exploit', 'Mitigating Controls\n(1 - 5)': 'Mitigating Controls', 'Mitigating Controls\nSelection': 'Mitigating Controls Selection', 'Ease of Exploit\n(1 - 5)':'Ease of Exploit', 'Risk Rating (1 - 125)':'Risk Rating'  })
    df['Date Opened'] =  df['Date Opened'].astype(str)
    df['Date Opened'] = df['Date Opened'].map(lambda x: x.lstrip('00:00:00').rstrip('00:00:00'))
    df = df.replace('\n',' ', regex=True)
    df.to_csv('test.csv', index = False)
    df_ = pd.read_csv('test.csv')
    df_.to_sql(con=database_connection, name='test', if_exists='replace')
    database_connection.close()

def sql_connection():
    connection = mysql.connector.connect(host='localhost',
                             database='vc',
                             user='root',
                             password='Thisis@rootuser2')
    return connection

def getdata():
       p=[]
       connect=sql_connection()
       cursor=connect.cursor(buffered=True)
       sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Critical"'''
       cursor.execute(sql_parameterized_query)
       connect.commit()
       for record in cursor:
              p.append(record[0])
       sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "High"'''
       cursor.execute(sql_parameterized_query)
       connect.commit()
       for record in cursor:
              p.append(record[0])
       sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Medium"'''
       cursor.execute(sql_parameterized_query)
       connect.commit()
       for record in cursor:
              p.append(record[0])
       sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Low"'''
       cursor.execute(sql_parameterized_query)
       connect.commit()
       for record in cursor:
              p.append(record[0])
       sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Informational"'''
       cursor.execute(sql_parameterized_query)
       connect.commit()
       for record in cursor:
              p.append(record[0])
       return p


       