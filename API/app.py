from flask import Flask, request, jsonify, redirect, url_for, render_template, send_file, render_template_string
import requests
import hashlib
import sys
import re
import random
import os
from fpdf import FPDF
import shutil
import json


app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

# ------------------------------------------------- Funções de password ---------------------------------------------- #

def generate_safe_pass(password):
    special_chars = ['!','@','#','$','%','&','*','(',')']
    numbers = ['0','1','2','3','4','5','6','7','8','9']
    new_password = ''
    master_special_count = 0
    special_count = 0
    password_count = 0
    for i in range(1,25*len(password)-1):
        rand_int = random.randint(1,5)
        if rand_int == 1 and special_count == 0:
            new_password += special_chars[random.randint(0,len(special_chars)-1)]
            special_count += 1
            master_special_count += 1
        elif rand_int == 2 and special_count == 0:
            new_password += numbers[random.randint(0,len(numbers)-1)]
            special_count += 1
        elif rand_int != 1 and rand_int != 2:
            try:
                new_password += password[password_count]
                password_count += 1
                special_count = 0
            except IndexError:
                special_count = 0
                if len(new_password) >= 2*len(password) and master_special_count > 2:

                    is_breached = check_new(new_password)
                    if is_breached == 1:
                        generate_safe_pass(password)
                    elif is_breached == -1:
                        new_password = 'None'

                    return new_password

def check_new(new_password):
    # Calcula o sha1 da password
    sha1pwd = hashlib.sha1(new_password.encode('utf-8')).hexdigest().upper()
    # Pega os cinco primeiros caracteres da senha em formato sha1
    sha1_head = sha1pwd[:5]
    # Pega os caracteres restantes da senha em formato sha1
    sha1_tail = sha1pwd[5:]

    # Para a API são passados os 5 primeiros caracteres em sha1
    url = 'https://api.pwnedpasswords.com/range/'+sha1_head
    try:
        r = requests.get(url)

        status_code = r.status_code
        if status_code != 200:
            return -1

        # Pega a resposta e separa o restante dos carateres da contagem
        hashes = (line.split(':') for line in r.text.splitlines())
        #print(list(hashes))
        count = 0
        for hash in list(hashes):
            # Se os caracteres restantes da senha sha1 forem iguais ao elemento de resposta coloque o count associado a esse hash
            if sha1_tail == hash[0]:
                count = hash[1]
                return 1

        return 0


    except requests.exceptions.ConnectTimeout:
        return -1
    except requests.exceptions.ConnectionError:
        return -1
    except requests.exceptions.SSLError:
        return -1

# ------------------------------------------------------------------------------------------------------------------------------------------------- #

# ------------------------------------------------------- Formatação do PDF -----------------------------------------------------------------------#

from fpdf import FPDF

class PDF(FPDF):
    def header(self):
        # Logo
        self.image('logo_pb.png', 10, 8, 30,15)
        self.image('logo_ft.png',170,8,30,15)
        self.set_auto_page_break(True,20)
        # Arial bold 15
        self.set_font('Arial', 'B', 15)
        # Move to the right
        #self.cell(80,20)
        # Title
        self.cell(190, 15, 'Relatório de Integridade de dados - Email', 0, 0, 'C')
        self.set_title('Relatório de Integridade de dados - Email')
        self.cell(300,60)
        # Line break
        self.ln(20)

    # Page footer
    def footer(self):
        # Position at 1.5 cm from bottom
        self.set_y(-15)
        # Arial italic 8
        self.set_font('Arial', 'I', 8)
        # Page number
        self.cell(0, 10, 'Page ' + str(self.page_no()) + '/{nb}', 0, 0, 'C')

def download_image(url, file_name):
    try:
        r = requests.get(url,stream=True)

        status_code = r.status_code
        if status_code != 200:
            return jsonify({"Response":"Error","Status":status_code})

        if r.headers.get('content-type') == "image/png":
            with open('./breached_images/'+file_name, 'wb') as out_file:
                shutil.copyfileobj(r.raw, out_file)
            del r
        else:
            os.system("cp ./error/error.jpeg ./breached_images/{}".format(file_name))

    except requests.exceptions.ConnectTimeout:
        os.system("cp ./error/error.jpeg ./breached_images/{}".format(file_name))
    except requests.exceptions.ConnectionError:
        os.system("cp ./error/error.jpeg ./breached_images/{}".format(file_name))
    except requests.exceptions.SSLError:
        os.system("cp ./error/error.jpeg ./breached_images/{}".format(file_name))

# ------------------------------------------------------------------------------------------------------------------------------------------------- #


# ------------------------------------------------------- Métodos da API -----------------------------------------------------------------------#
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/passwordpage')
def render_password():
    return render_template("password.html")

@app.route('/emailpage')
def render_email():
    return render_template("email.html")

@app.route('/password',methods=['POST'])
def password():
    # Pega o campo password do form da página HTML
    password= request.form['password']
    if password == "":
        return jsonify({"Response":"Error","Status":"400"}),400
    # Calcula o sha1 da password
    sha1pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # Pega os cinco primeiros caracteres da senha em formato sha1
    sha1_head = sha1pwd[:5]
    # Pega os caracteres restantes da senha em formato sha1
    sha1_tail = sha1pwd[5:]

    # Para a API são passados os 5 primeiros caracteres em sha1
    url = 'https://api.pwnedpasswords.com/range/'+sha1_head
    try:
        r = requests.get(url)

        status_code = r.status_code
        if status_code != 200:
            return jsonify({"Response":"Error","Status":status_code})

        # Pega a resposta e separa o restante dos carateres da contagem
        hashes = (line.split(':') for line in r.text.splitlines())
        #print(list(hashes))
        count = 0
        for hash in list(hashes):
            # Se os caracteres restantes da senha sha1 forem iguais ao elemento de resposta coloque o count associado a esse hash
            if sha1_tail == hash[0]:
                count = hash[1]

        if count != 0:
            new_passwd = generate_safe_pass(password)
            return jsonify({"Status":status_code,"Resposta":"Sua senha foi encontrada {} vezes nas bases de dados vazadas.".format(count),"Senha recomendada":new_passwd})
        
        return jsonify({"Status":status_code,"Resposta":"Sua senha foi encontrada {} vezes nas bases de dados vazadas.".format(count)})

    except requests.exceptions.ConnectTimeout:
        return jsonify({"Resposta":"Tempo de conexão excedida com: {}".format(url)})
    except requests.exceptions.ConnectionError:
        return jsonify({"Resposta":"Erro de conexão com: {}".format(url)})
    except requests.exceptions.SSLError:
        return jsonify({"Resposta":"Erro de conexão SSL com: {}".format(url)})

    return  jsonify({"Senha":password,"Hash":sha1pwd,"Head":sha1_head,"Tail":sha1_tail})

@app.route('/email',methods=['POST'])
def email():
    # Pega o campo email do form da página HTML
    email = request.form['email']

    match = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',email)
    if len(match) == 0:
        return jsonify({'Response':'Sent parameter (email) is not an email!','Status':400}),400

    url = "https://haveibeenpwned.com/api/v2/breachedaccount/"+email
    #url = 'https://api.github.com/events'
    try:
        r = requests.get(url)

        status_code = r.status_code
        if status_code != 200:
            #return render_template("email_response_ok.html")
            return jsonify({"Response":"Email não vazado","Status":str(status_code)})

        #response_data = r.headers['content-type']#list(r.text)
        response_data = r.json()

        outPut = jsonify({"Response":response_data,"Email":email,"Status":str(status_code)}),200
        #html = "<style> hr{background-color: black}body{background-color: black;background-image: url('https://media.giphy.com/media/rWY9ySfjytitq/giphy.gif');}.card {margin: 0 auto;float: none;margin-bottom: 10px;}</style><body><script></script></body>"

        #return

        #return render_template("email_response_data.html"),email

        #info = r.text

        #return info

        #return html
        return outPut

    except requests.exceptions.ConnectTimeout:
        return jsonify({"Error":"Tempo de conexão excedida com: {}".format(url)})
    except requests.exceptions.ConnectionError:
        return jsonify({"Error":"Erro de conexão com: {}".format(url)})
    except requests.exceptions.SSLError:
        return jsonify({"Error":"Erro de conexão SSL com: {}".format(url)})

def get_email(email):
    return email

@app.route('/report',methods=['POST'])
def generate_report():

    template_json = request.get_json(force=True)
    print(template_json)

    #os.system("rm -f ./report.pdf")
    pdf = PDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_font('Times', '', 8)
    pdf.set_fill_color(100, 10, 5)
    pdf.ln(20)
    pdf.cell(0,5,'Email: {}'.format(template_json["Email"]),1,0,'C')
    pdf.ln(10)
    loop_y = 0.5
    loop_x = 1
    for response in template_json['Response']:

        #download_image(response["LogoPath"],response['Name']+".png")

        pdf.cell(0,5,'Vazado em: {}'.format(response['Name']),1,0,'C')
        pdf.ln(8)
        pdf.set_font('Times', 'B', 10)
        pdf.cell(0,5,'Nome do domínio: ')
        pdf.ln(5)
        pdf.set_font('Times', '', 8)
        pdf.multi_cell(0,5,response['Domain'])
        pdf.ln(2)

        pdf.set_font('Times', 'B', 10)
        pdf.cell(0,5,'Data do vazamento: ')
        pdf.ln(5)
        pdf.set_font('Times', '', 8)
        pdf.multi_cell(0,5,response['BreachDate'])
        pdf.ln(2)

        pdf.set_font('Times', 'B', 10)
        pdf.cell(0,5,'Dados vazados: ')
        pdf.ln(5)
        pdf.set_font('Times', '', 8)
        text = ""
        i = 0
        for datatype in response["DataClasses"]:
            if len(response["DataClasses"])-1 == i:
                text += "{}".format(datatype)
            else:
                text += "{}, ".format(datatype)
            i += 1
        pdf.multi_cell(0,5,text)
        pdf.ln(2)

        #pdf.image('./breached_images/'+response['Name']+'.png',(loop_x)*140,loop_y*150,30,15)

        pdf.set_font('Times', 'B', 10)
        pdf.cell(0,5,'Descrição do vazamento: ')
        pdf.ln(7)
        pdf.set_font('Times', '', 8)
        pdf.multi_cell(0, 5, response['Description'])
        pdf.ln(5)

    pdf.output('report.pdf', 'F')
    path = './report.pdf'
    return jsonify({"Status":"Success"}),200
    #return send_file(path, as_attachment=True)



@app.route('/report-download',methods=['GET'])
def download():
    path = 'report.pdf'
    return send_file(path,as_attachment=True)

# ------------------------------------------------------------------------------------------------------------------------------------------------- #

if __name__ == "__main__":
    host = "127.0.0.1"
    port = 8080
    app.run(debug=True, host=host, port=port, use_reloader=True, ssl_context=('certificate/cert.pem','certificate/key.pem'))
