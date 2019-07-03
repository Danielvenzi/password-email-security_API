from flask import Flask, request, jsonify, redirect, url_for, render_template, send_file
import requests
import hashlib
import sys
import re
import random
import os
from fpdf import FPDF
import shutil

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
        return jsonify({"Response":response_data,"Email":email}),200
        


    except requests.exceptions.ConnectTimeout:
        return jsonify({"Error":"Tempo de conexão excedida com: {}".format(url)})
    except requests.exceptions.ConnectionError:
        return jsonify({"Error":"Erro de conexão com: {}".format(url)})
    except requests.exceptions.SSLError:
        return jsonify({"Error":"Erro de conexão SSL com: {}".format(url)})


@app.route('/report',methods=['POST'])
def generate_report():

    template_json = request.get_json(force=True)

#     template_json = {
#   "Email": "franciscolopescaldas@gmail.com", 
#   "Response": [
#     {
#       "AddedDate": "2016-08-31T00:19:19Z", 
#       "BreachDate": "2012-07-01", 
#       "DataClasses": [
#         "Email addresses", 
#         "Passwords"
#       ], 
#       "Description": "In mid-2012, Dropbox suffered a data breach which exposed the stored credentials of tens of millions of their customers. In August 2016, <a href=\"https://motherboard.vice.com/read/dropbox-forces-password-resets-after-user-credentials-exposed\" target=\"_blank\" rel=\"noopener\">they forced password resets for customers they believed may be at risk</a>. A large volume of data totalling over 68 million records <a href=\"https://motherboard.vice.com/read/hackers-stole-over-60-million-dropbox-accounts\" target=\"_blank\" rel=\"noopener\">was subsequently traded online</a> and included email addresses and salted hashes of passwords (half of them SHA1, half of them bcrypt).", 
#       "Domain": "dropbox.com", 
#       "IsFabricated": "false", 
#       "IsRetired": "false", 
#       "IsSensitive": "false", 
#       "IsSpamList": "false", 
#       "IsVerified": "true", 
#       "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Dropbox.png", 
#       "ModifiedDate": "2016-08-31T00:19:19Z", 
#       "Name": "Dropbox", 
#       "PwnCount": 68648009, 
#       "Title": "Dropbox"
#     }, 
#     {
#       "AddedDate": "2016-09-20T20:00:49Z", 
#       "BreachDate": "2012-03-22", 
#       "DataClasses": [
#         "Email addresses", 
#         "Passwords", 
#         "Usernames", 
#         "Website activity"
#       ], 
#       "Description": "In March 2012, the music website <a href=\"https://techcrunch.com/2016/09/01/43-million-passwords-hacked-in-last-fm-breach/\" target=\"_blank\" rel=\"noopener\">Last.fm was hacked</a> and 43 million user accounts were exposed. Whilst <a href=\"http://www.last.fm/passwordsecurity\" target=\"_blank\" rel=\"noopener\">Last.fm knew of an incident back in 2012</a>, the scale of the hack was not known until the data was released publicly in September 2016. The breach included 37 million unique email addresses, usernames and passwords stored as unsalted MD5 hashes.", 
#       "Domain": "last.fm", 
#       "IsFabricated": "false", 
#       "IsRetired": "false", 
#       "IsSensitive": "false", 
#       "IsSpamList": "false", 
#       "IsVerified": "true", 
#       "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Lastfm.png", 
#       "ModifiedDate": "2016-09-20T20:00:49Z", 
#       "Name": "Lastfm", 
#       "PwnCount": 37217682, 
#       "Title": "Last.fm"
#     }, 
#     {
#       "AddedDate": "2016-05-21T21:35:40Z", 
#       "BreachDate": "2012-05-05", 
#       "DataClasses": [
#         "Email addresses", 
#         "Passwords"
#       ], 
#       "Description": "In May 2016, <a href=\"https://www.troyhunt.com/observations-and-thoughts-on-the-linkedin-data-breach\" target=\"_blank\" rel=\"noopener\">LinkedIn had 164 million email addresses and passwords exposed</a>. Originally hacked in 2012, the data remained out of sight until being offered for sale on a dark market site 4 years later. The passwords in the breach were stored as SHA1 hashes without salt, the vast majority of which were quickly cracked in the days following the release of the data.", 
#       "Domain": "linkedin.com", 
#       "IsFabricated": "false", 
#       "IsRetired": "false", 
#       "IsSensitive": "false", 
#       "IsSpamList": "false", 
#       "IsVerified": "true", 
#       "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/LinkedIn.png", 
#       "ModifiedDate": "2016-05-21T21:35:40Z", 
#       "Name": "LinkedIn", 
#       "PwnCount": 164611595, 
#       "Title": "LinkedIn"
#     }, 
#     {
#       "AddedDate": "2016-10-12T09:09:11Z", 
#       "BreachDate": "2016-10-08", 
#       "DataClasses": [
#         "Dates of birth", 
#         "Email addresses", 
#         "Genders", 
#         "IP addresses", 
#         "Job titles", 
#         "Names", 
#         "Phone numbers", 
#         "Physical addresses"
#       ], 
#       "Description": "In October 2016, a large Mongo DB file containing tens of millions of accounts <a href=\"https://twitter.com/0x2Taylor/status/784544208879292417\" target=\"_blank\" rel=\"noopener\">was shared publicly on Twitter</a> (the file has since been removed). The database contained over 58M unique email addresses along with IP addresses, names, home addresses, genders, job titles, dates of birth and phone numbers. The data was subsequently <a href=\"http://news.softpedia.com/news/hacker-steals-58-million-user-records-from-data-storage-provider-509190.shtml\" target=\"_blank\" rel=\"noopener\">attributed to &quot;Modern Business Solutions&quot;</a>, a company that provides data storage and database hosting solutions. They've yet to acknowledge the incident or explain how they came to be in possession of the data.", 
#       "Domain": "modbsolutions.com", 
#       "IsFabricated": "false", 
#       "IsRetired": "false", 
#       "IsSensitive": "false", 
#       "IsSpamList": "false", 
#       "IsVerified": "true", 
#       "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/ModernBusinessSolutions.png", 
#       "ModifiedDate": "2016-10-12T09:09:11Z", 
#       "Name": "ModernBusinessSolutions", 
#       "PwnCount": 58843488, 
#       "Title": "Modern Business Solutions"
#     }, 
#     {
#       "AddedDate": "2019-02-20T21:04:04Z", 
#       "BreachDate": "2017-10-26", 
#       "DataClasses": [
#         "Email addresses", 
#         "Passwords"
#       ], 
#       "Description": "In October 2017, the genealogy website <a href=\"https://blog.myheritage.com/2018/06/myheritage-statement-about-a-cybersecurity-incident/\" target=\"_blank\" rel=\"noopener\">MyHeritage suffered a data breach</a>. The incident was reported 7 months later after a security researcher discovered the data and contacted MyHeritage. In total, more than 92M customer records were exposed and included email addresses and salted SHA-1 password hashes. In 2019, <a href=\"https://www.theregister.co.uk/2019/02/11/620_million_hacked_accounts_dark_web/\" target=\"_blank\" rel=\"noopener\">the data appeared listed for sale on a dark web marketplace</a> (along with several other large breaches) and subsequently began circulating more broadly. The data was provided to HIBP by a source who requested it be attributed to &quot;BenjaminBlue@exploit.im&quot;.", 
#       "Domain": "myheritage.com", 
#       "IsFabricated": "false", 
#       "IsRetired": "false", 
#       "IsSensitive": "false", 
#       "IsSpamList": "false", 
#       "IsVerified": "true", 
#       "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/MyHeritage.png", 
#       "ModifiedDate": "2019-02-20T21:04:04Z", 
#       "Name": "MyHeritage", 
#       "PwnCount": 91991358, 
#       "Title": "MyHeritage"
#     }
#   ]
# }


    os.system("rm -f ./report.pdf")
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
    return send_file(path, as_attachment=True)


# ------------------------------------------------------------------------------------------------------------------------------------------------- #

if __name__ == "__main__":
    host = "127.0.0.1"
    port = 8080
    app.run(debug=True, host=host, port=port, use_reloader=True, ssl_context=('certificate/cert.pem','certificate/key.pem'))