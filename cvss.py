from flask import Flask, render_template, request
import matplotlib.pyplot as plt
import os
import math

app = Flask(__name__)
image= os.path.join('static', 'images')
app.config['UPLOAD_FOLDER']= image

@app.route('/', methods= ['get', 'post'])
def index():
    return render_template('index.html')

def roundup(n):
    return math.ceil(n* 10)/ 10

def col(n, ls):
    if 9<= n<= 10:
        return ls[0]
    elif 7<= n< 9:
        return ls[1]
    elif 4<= n< 7:
        return ls[2]
    else:
        return ls[3]

@app.route('/cvss', methods=['get', 'post'])
def cvss():
    if request.method== 'POST':
        av= float(request.form['av'])
        ac= float(request.form['ac'])  
        pr= float(request.form['pr'])  
        ui= float(request.form['ui'])  
        s= float(request.form['s'])    
        c= float(request.form['c'])    
        i= float(request.form['i'])    
        a= float(request.form['a'])    
        e=   float(request.form['e'])
        rl=  float(request.form['rl'])
        rc=  float(request.form['rc'])
        mav= float(request.form['mav'])
        mac= float(request.form['mac'])
        mpr= float(request.form['mpr'])
        mui= float(request.form['mui'])
        ms=  float(request.form['ms'])
        mc=  float(request.form['mc'])
        mi=  float(request.form['mi'])
        ma=  float(request.form['ma'])
        cr=  float(request.form['cr'])
        ir=  float(request.form['ir'])
        ar=  float(request.form['ar'])

    iss= 1- ((1- c)* (1- i)* (1- a))

    if s== 0:
        imp= 6.42* iss
        if pr== 0.62:
            pr= 0.68
        elif pr== 0.27:
            pr= 0.5
    else:
        imp= (7.52* (iss- 0.029))- (3.25* ((iss- 0.02)** 15))

    exp= 8.22* av* ac* pr* ui
    if imp<= 0: 
        b_s= 0
    elif s== 0:
        b_s= roundup(min(imp+ exp, 10))
    else:
        b_s= roundup(min(1.08* (imp+ exp), 10))

    t_s= roundup(b_s* e* rl* rc)

    miss= min(1- ((1- (mc* cr))*(1- (mi* ir))*(1- (ma* ar))), 0.915)

    if ms== 0:
        m_imp= 6.42* miss
        if pr== 0.62:
            pr= 0.68
        elif pr== 0.27:
            pr= 0.5
    else:
        m_imp= (7.52* (iss- 0.029))- (3.25* (((iss* 0.9731)- 0.02)** 13))

    m_exp= 8.22* mav* mac* mpr* mui
    if m_imp<= 0: 
        e_s= 0
    elif ms== 0:
        e_s= roundup(roundup(min(m_imp+ m_exp, 10))* e* rl* rc)
    else:
        e_s= roundup(roundup(min(1.08* (m_imp+ m_exp), 10))* e* rl* rc)

    if e_s== 0:
        o_s= t_s
        if t_s== 0:
            o_s= b_s
    else:
        o_s= e_s

    x= ['Overall', 'Modified Impact', 'Environmental', 'Temporal', 'Exploitability', 'Impact', 'Base']
    y= [o_s, m_imp, e_s, t_s, exp, imp, b_s]
    colors= []
    for i in range(len(y)):
        if round(y[i], 1)<= 0:
            y[i]= 0
        else:
            y[i]= round(y[i], 1)
        colors.append(col(y[i], ['red', 'orange', 'yellow', 'green']))

    plt.clf()
    plt.grid(axis= 'x')
    plt.xlim([0, 10])
    plt.barh(x, y, color= colors)
    plt.yticks(color='w')

    bgcol= ['danger', 'warning', 'success', 'info']
    rating= ['Critical', 'High', 'Medium', 'Low']
    bg= col(o_s, [0, 1, 2, 3])
    for i in range(len(x)):
        plt.text(0.3, i- 0.1, '%2.1f : %s'%(y[i], x[i]))

    plt.savefig('static/images/graph.png')
    graph= '/' + os.path.join(app.config['UPLOAD_FOLDER'], 'graph.png')

    return render_template('cvss.html', graph= graph, scores= y, col= bgcol[bg], rating= rating[bg])


if __name__ == '__main__':
    app.run(debug=True)
