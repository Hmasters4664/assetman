import pymysql
from app import app
from database_config import mysql
from flask import render_template
from flask import jsonify
from flask import flash, request
import json
import mysql.connector
import re
from mysql.connector import Error
import datetime
import os
from mysql.connector import errorcode
from functions import getdata,insert

UPLOAD_FOLDER = '/home/hassani/Desktop/upload'
ALLOWED_EXTENSIONS = set(['xls', 'xlsm'])

def sql_connection():
        connection = mysql.connector.connect(host='localhost',
                             database='vc',
                             user='root',
                             password='Thisis@rootuser2')
        return connection



@app.route('/show',methods=['GET'])
def show():
    try:
        connect=sql_connection()
        cursor=connect.cursor(buffered=True)
        sql_parameterized_query='''select * from vc.better_vc'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
        r = [dict((cursor.description[i][0], value)
              for i, value in enumerate(row)) for row in cursor.fetchall()]
        return jsonify({'Assessments' :r})

    except Exception as e:
        print(e)
    finally:
	    cursor.close() 
	    connect.close()

@app.route('/table',methods=['GET'])
def table():
    try:
        connect=sql_connection()
        cursor=connect.cursor(buffered=True)
        sql_parameterized_query='''select `Accountable Vulnerability Owner`, `BSA Reference`, `Engagement Name`, `Date Opened`, `Vulnerability Platform`, `Risk`, `Risk Rating`, `Test Type`, `Security Risk Consultant`, `Name of Pen Tester`, `Vulnerability Name` from vc.better_vc'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
        data = cursor.fetchall()
        return render_template('table.html', data=data)

    except Exception as e:
        print(e)
    finally:
	    cursor.close() 
	    connect.close()

@app.route('/test', methods=['GET'])
def dashboard():
    try:
        p=[]
        p=getdata()
        #print(p)
        values=map(int,p)
        appl=appplication()
        infrs=infrastructure()
        sys=sysbuild()
        db=Database()
        NSA=NetSecArch()
        FN=FND()
        CodeR=CR()
        SecCo=SC()
        print(appl)
        print(infrs)
        legend = 'Vulnerability frequency By type'
        legend2 = 'Web application vulnerabilities'
        labels = ["Critical", "High", "Medium", "Low", "Informational"]
        labels2 = ["Critical", "High", "Medium", "Low", "Informational"]				
        return render_template('template.html',value1=p[0],value2=p[1],value3=p[2],value4=p[3],value5=p[4],values=values, labels=labels, legend=legend, labels2=labels2,appl=appl,infr=infrs,legend2=legend2)


    except Exception as e:
        print(e)

@app.route('/stats', methods=['GET'])
def stats():
    try:
        connect=sql_connection()
        cursor=connect.cursor(buffered=True)
        sql_parameterized_query='''select count(*) from vc.better_vc where Risk in ("Critical","High","Medium","Low","Informational") group by Risk'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
        r = [dict((cursor.description[i][0], value)
              for i, value in enumerate(row)) for row in cursor.fetchall()]
        return jsonify({'Stuff' :r})

    except Exception as e:
		print(e)
    finally:
	    cursor.close() 
	    connect.close()

@app.route('/count', methods=['GET'])
def count():
    try:
        connect=sql_connection()
        cursor=connect.cursor(buffered=True)
        sql_parameterized_query='''select count(*) from vc.better_vc'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
        r = [dict((cursor.description[i][0], value)
              for i, value in enumerate(row)) for row in cursor.fetchall()]
        return jsonify({'Assessments' :r})

    except Exception as e:
		print(e)
    finally:
	    cursor.close() 
	    connect.close()
 
    
@app.errorhandler(404)
def not_found(error=None):
    message = {
        'status': 404,
        'message': 'Not Found: ' + request.url,
    }
    resp = jsonify(message)
    resp.status_code = 404

    return resp

@app.route('/low', methods=['GET'])
def low():
    try:
        connect=sql_connection()
        cursor=connect.cursor(buffered=True)
        sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Low"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
        r = [dict((cursor.description[i][0], value)
              for i, value in enumerate(row)) for row in cursor.fetchall()]
        return jsonify({'Stuff' :r})

    except Exception as e:
		print(e)
    finally:
	    cursor.close() 
	    connect.close()

@app.route('/medium', methods=['GET'])
def medium():
    try:
        connect=sql_connection()
        cursor=connect.cursor(buffered=True)
        sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Medium"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
        r = [dict((cursor.description[i][0], value)
              for i, value in enumerate(row)) for row in cursor.fetchall()]
        return jsonify({'Stuff' :r})

    except Exception as e:
		print(e)
    finally:
	    cursor.close() 
	    connect.close()

@app.route('/high', methods=['GET'])
def high():
    try:
        connect=sql_connection()
        cursor=connect.cursor(buffered=True)
        sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "High"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
        r = [dict((cursor.description[i][0], value)
              for i, value in enumerate(row)) for row in cursor.fetchall()]
        return jsonify({'Stuff' :r})

    except Exception as e:
		print(e)
    finally:
	    cursor.close() 
	    connect.close()

@app.route('/api/search', methods=['GET'])
def search():
        try:
                BSA=str(request.args['BSA'])
                BSA = re.sub(r'([^\s\w]|_)+','',BSA)
                print(BSA)
                if not BSA or not BSA.strip():
                        BSA = "%"
                print(BSA)
                connect=sql_connection()
                cursor=connect.cursor(buffered=True)
                #sql_parameterized_query="""select * from vc.better_vc where `BSA Reference`= %s """
                #cursor.execute("""select `Accountable Vulnerability Owner`, `BSA Reference`, `Engagement Name`, `Date Opened`, `Vulnerability Platform`, `Risk`, `Risk Rating`, `Test Type`, 
                #`Security Risk Consultant`, `Name of Pen Tester`, `Vulnerability Name` from vc.better_vc where `BSA Reference` like %s""",(BSA,))

                cursor.execute("""select `Accountable Vulnerability Owner`, `BSA Reference`, `Engagement Name`, `Date Opened`, `Vulnerability Platform`, `Risk`, `Risk Rating`, `Test Type`, 
                `Security Risk Consultant`, `Name of Pen Tester`, `Vulnerability Name` from vc.better_vc where `BSA Reference` like CONCAT('%',%s,'%') or `Vulnerability Name` like CONCAT('%',%s,'%') or `Engagement Name` like CONCAT('%',%s,'%')""",(BSA,BSA,BSA,))

                connect.commit()
                data = cursor.fetchall()
                d= json.dumps(data)
                #print(data)
                print(d)
                return d
                
        except Exception as e:
                print(e)
        finally:
                cursor.close() 
	        connect.close() 

def appplication():
    try:
	p=[]
        connect=sql_connection()
        cursor=connect.cursor(buffered=True)
        sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Critical" and `Vulnerability Platform`="Web Application"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "High" and `Vulnerability Platform`="Web Application"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Medium" and `Vulnerability Platform`="Web Application"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Low" and `Vulnerability Platform`="Web Application"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Informational" and `Vulnerability Platform`="Web Application"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	values=map(int,p)	
        return values


    except Exception as e:
		print(e)
    finally:
	    cursor.close() 
	    connect.close()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload',methods=['GET','POST'])
def upload():
        if request.method == 'POST':
                if 'file' not in request.files:
                        return redirect(request.url)
        file = request.files['file']

        if file.filename == '':
                return redirect(request.url)
        if file:
                filename = 'BSA-{date:%Y-%m-%d_%H:%M:%S}.xls'.format( date=datetime.datetime.now() )
                file.save(os.path.join(UPLOAD_FOLDER, filename))
                insert(filename)
                return jsonify('ok')

@app.route('/update',methods=['GET'])
def update():
        return render_template('upload.html')

def infrastructure():
    try:
	p=[]
        connect=sql_connection()
        cursor=connect.cursor(buffered=True)
        sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Critical" and `Vulnerability Platform`="Infrastructure"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "High" and `Vulnerability Platform`="Infrastructure"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Medium" and `Vulnerability Platform`="Infrastructure"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Low" and `Vulnerability Platform`="Infrastructure"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Informational" and `Vulnerability Platform`="Infrastructure"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	values=map(int,p)	
        return values


    except Exception as e:
		print(e)
    finally:
	    cursor.close() 
	    connect.close()

def sysbuild():
    try:
	p=[]
        connect=sql_connection()
        cursor=connect.cursor(buffered=True)
        sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Critical" and `Vulnerability Platform`="System Build"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "High" and `Vulnerability Platform`="System Build"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Medium" and `Vulnerability Platform`="System Build"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Low" and `Vulnerability Platform`="System Build"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Informational" and `Vulnerability Platform`="System Build"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	values=map(int,p)	
        return values


    except Exception as e:
		print(e)
    finally:
	    cursor.close() 
	    connect.close()

def Database():
    try:
	p=[]
        connect=sql_connection()
        cursor=connect.cursor(buffered=True)
        sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Critical" and `Vulnerability Platform`="Database"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "High" and `Vulnerability Platform`="Database"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Medium" and `Vulnerability Platform`="Database"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Low" and `Vulnerability Platform`="Database"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Informational" and `Vulnerability Platform`="Database"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	values=map(int,p)	
        return values


    except Exception as e:
		print(e)
    finally:
	    cursor.close() 
	    connect.close()

def NetSecArch():
    try:
	p=[]
        connect=sql_connection()
        cursor=connect.cursor(buffered=True)
        sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Critical" and `Vulnerability Platform`="Network Security Architecture"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "High" and `Vulnerability Platform`="Network Security Architecture"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Medium" and `Vulnerability Platform`="Network Security Architecture"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Low" and `Vulnerability Platform`="Network Security Architecture"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Informational" and `Vulnerability Platform`="Network Security Architecture"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	values=map(int,p)	
        return values


    except Exception as e:
		print(e)
    finally:
	    cursor.close() 
	    connect.close()

def FND():
    try:
	p=[]
        connect=sql_connection()
        cursor=connect.cursor(buffered=True)
        sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Critical" and `Vulnerability Platform`="Firewall/Network Device"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "High" and `Vulnerability Platform`="Firewall/Network Device"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Medium" and `Vulnerability Platform`="Firewall/Network Device"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Low" and `Vulnerability Platform`="Firewall/Network Device"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Informational" and `Vulnerability Platform`="Firewall/Network Device"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	values=map(int,p)	
        return values


    except Exception as e:
		print(e)
    finally:
	    cursor.close() 
	    connect.close()

def CR():
    try:
	p=[]
        connect=sql_connection()
        cursor=connect.cursor(buffered=True)
        sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Critical" and `Vulnerability Platform`="Code Review"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "High" and `Vulnerability Platform`="Code Review"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Medium" and `Vulnerability Platform`="Code Review"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Low" and `Vulnerability Platform`="Code Review"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Informational" and `Vulnerability Platform`="Code Review"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	values=map(int,p)	
        return values


    except Exception as e:
		print(e)
    finally:
	    cursor.close() 
	    connect.close()

def SC():
    try:
	p=[]
        connect=sql_connection()
        cursor=connect.cursor(buffered=True)
        sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Critical" and `Vulnerability Platform`="Security Controls"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "High" and `Vulnerability Platform`="Security Controls"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Medium" and `Vulnerability Platform`="Security Controls"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Low" and `Vulnerability Platform`="Security Controls"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	sql_parameterized_query='''select count(*) from vc.better_vc where Risk= "Informational" and `Vulnerability Platform`="Security Controls"'''
        cursor.execute(sql_parameterized_query)
        connect.commit()
	for record in cursor:
		p.append(record[0])
	values=map(int,p)	
        return values


    except Exception as e:
		print(e)
    finally:
	    cursor.close() 
	    connect.close()

if __name__ == "__main__":
    app.run()
