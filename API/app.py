from flask import Flask, request, jsonify, redirect, url_for, render_template
import requests
import hashlib
import sys
import re
import random

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

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
            return jsonify({"Status":status_code,"Resposta":"Sua senha foi encontrada {} vezes nas bases de dados vazadas.".format(count),"Senha recomendada (não vazada)":new_passwd})
        
        return jsonify({"Status":status_code,"Resposta":"Sua senha foi encontrada {} vezes nas bases de dados vazadas.".format(count)})
    
    except requests.exceptions.ConnectTimeout:
        return jsonify({"Error":"Tempo de conexão excedida com: {}".format(url)})
    except requests.exceptions.ConnectionError:
        return jsonify({"Error":"Erro de conexão com: {}".format(url)})
    except requests.exceptions.SSLError:
        return jsonify({"Error":"Erro de conexão SSL com: {}".format(url)})

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
            return jsonify({"Response":"Error","Status":status_code})

        #response_data = r.headers['content-type']#list(r.text)
        response_data = r.json()

        #print(response_data.encode('UTF-8'))
        #return jsonify("Status":status_code,"Resposta":"")
        return jsonify({"Response":response_data}),200
        


    except requests.exceptions.ConnectTimeout:
        return jsonify({"Error":"Tempo de conexão excedida com: {}".format(url)})
    except requests.exceptions.ConnectionError:
        return jsonify({"Error":"Erro de conexão com: {}".format(url)})
    except requests.exceptions.SSLError:
        return jsonify({"Error":"Erro de conexão SSL com: {}".format(url)})

if __name__ == "__main__":
    host = "127.0.0.1"
    port = 8080
    app.run(debug=True, host=host, port=port, use_reloader=True)