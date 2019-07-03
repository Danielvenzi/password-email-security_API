import re
import random
import requests
import json

# string_with_email = "This is a string with a email: danielven"
# match = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',string_with_email)
# print(match)

# for i in range(10):
#     print(i)

# def generate_safe_pass(password):
#     special_chars = ['!','@','#','$','%','&','*','(',')']
#     numbers = ['0','1','2','3','4','5','6','7','8','9']
#     new_password = ''
#     master_special_count = 0
#     special_count = 0
#     password_count = 0
#     for i in range(1,25*len(password)-1):
#         rand_int = random.randint(1,5)
#         if rand_int == 1 and special_count == 0:    
#             new_password += special_chars[random.randint(0,len(special_chars)-1)]
#             special_count += 1
#             master_special_count += 1
#         elif rand_int == 2 and special_count == 0:
#             new_password += numbers[random.randint(0,len(numbers)-1)]
#             special_count += 1
#         elif rand_int != 1 and rand_int != 2:
#             try:
#                 new_password += password[password_count]
#                 password_count += 1
#                 special_count = 0
#             except IndexError:
#                 special_count = 0
#                 if len(new_password) >= 2*len(password) and master_special_count > 2:
#                     print(new_password)
#                     return new_password


# template_json = {
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

# template_json = {
#   "Email": "danielvenzi@hotmail.com", 
#   "Response": [
#     {
#       "AddedDate": "2016-07-07T23:00:10Z", 
#       "BreachDate": "2013-05-05", 
#       "DataClasses": [
#         "Dates of birth", 
#         "Email addresses", 
#         "Genders", 
#         "Geographic locations", 
#         "IP addresses", 
#         "Names", 
#         "Passwords", 
#         "Usernames"
#       ], 
#       "Description": "In May 2016, <a href=\"http://motherboard.vice.com/read/neopets-hack-another-day-another-hack-tens-of-millions-of-neopets-accounts\" target=\"_blank\" rel=\"noopener\">a set of breached data originating from the virtual pet website &quot;Neopets&quot; was found being traded online</a>. Allegedly hacked &quot;several years earlier&quot;, the data contains sensitive personal information including birthdates, genders and names as well as almost 27 million unique email addresses. Passwords were stored in plain text and IP addresses were also present in the breach.", 
#       "Domain": "neopets.com", 
#       "IsFabricated": False, 
#       "IsRetired": False, 
#       "IsSensitive": False, 
#       "IsSpamList": False, 
#       "IsVerified": True, 
#       "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Neopets.png", 
#       "ModifiedDate": "2016-07-07T23:00:10Z", 
#       "Name": "Neopets", 
#       "PwnCount": 26892897, 
#       "Title": "Neopets"
#     }
#   ]
# }

false = 0
true = 1

# template_json = {
#   "Email": "kfourinho@hotmail.com", 
#   "Response": [
#     {
#       "AddedDate": "2017-06-01T05:59:24Z", 
#       "BreachDate": "2017-05-11", 
#       "DataClasses": [
#         "Email addresses", 
#         "Passwords", 
#         "Usernames"
#       ], 
#       "Description": "In May 2017, the education platform <a href=\"https://motherboard.vice.com/en_us/article/hacker-steals-millions-of-user-account-details-from-education-platform-edmodo\" target=\"_blank\" rel=\"noopener\">Edmodo was hacked</a> resulting in the exposure of 77 million records comprised of over 43 million unique customer email addresses. The data was consequently published to a popular hacking forum and made freely available. The records in the breach included usernames, email addresses and bcrypt hashes of passwords.", 
#       "Domain": "edmodo.com", 
#       "IsFabricated": false, 
#       "IsRetired": false, 
#       "IsSensitive": false, 
#       "IsSpamList": false, 
#       "IsVerified": true, 
#       "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Edmodo.png", 
#       "ModifiedDate": "2017-06-01T05:59:24Z", 
#       "Name": "Edmodo", 
#       "PwnCount": 43423561, 
#       "Title": "Edmodo"
#     }, 
#     {
#       "AddedDate": "2016-01-24T16:27:23Z", 
#       "BreachDate": "2012-12-17", 
#       "DataClasses": [
#         "Email addresses", 
#         "Passwords", 
#         "Usernames"
#       ], 
#       "Description": "In December 2012, the multiplayer online battle arena game known as <a href=\"http://www.heroesofnewerth.com/\" target=\"_blank\" rel=\"noopener\">Heroes of Newerth</a> <a href=\"https://www.reddit.com/r/HeroesofNewerth/comments/14zj2p/i_am_the_guy_who_hacked_hon/\" target=\"_blank\" rel=\"noopener\"> was hacked</a> and over 8 million accounts extracted from the system. The compromised data included usernames, email addresses and passwords.", 
#       "Domain": "heroesofnewerth.com", 
#       "IsFabricated": false, 
#       "IsRetired": false, 
#       "IsSensitive": false, 
#       "IsSpamList": false, 
#       "IsVerified": true, 
#       "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/HeroesOfNewerth.png", 
#       "ModifiedDate": "2016-01-24T16:27:23Z", 
#       "Name": "HeroesOfNewerth", 
#       "PwnCount": 8089103, 
#       "Title": "Heroes of Newerth"
#     }, 
#     {
#       "AddedDate": "2016-07-07T23:00:10Z", 
#       "BreachDate": "2013-05-05", 
#       "DataClasses": [
#         "Dates of birth", 
#         "Email addresses", 
#         "Genders", 
#         "Geographic locations", 
#         "IP addresses", 
#         "Names", 
#         "Passwords", 
#         "Usernames"
#       ], 
#       "Description": "In May 2016, <a href=\"http://motherboard.vice.com/read/neopets-hack-another-day-another-hack-tens-of-millions-of-neopets-accounts\" target=\"_blank\" rel=\"noopener\">a set of breached data originating from the virtual pet website &quot;Neopets&quot; was found being traded online</a>. Allegedly hacked &quot;several years earlier&quot;, the data contains sensitive personal information including birthdates, genders and names as well as almost 27 million unique email addresses. Passwords were stored in plain text and IP addresses were also present in the breach.", 
#       "Domain": "neopets.com", 
#       "IsFabricated": false, 
#       "IsRetired": false, 
#       "IsSensitive": false, 
#       "IsSpamList": false, 
#       "IsVerified": true, 
#       "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Neopets.png", 
#       "ModifiedDate": "2016-07-07T23:00:10Z", 
#       "Name": "Neopets", 
#       "PwnCount": 26892897, 
#       "Title": "Neopets"
#     }, 
#     {
#       "AddedDate": "2016-05-29T22:59:04Z", 
#       "BreachDate": "2013-02-28", 
#       "DataClasses": [
#         "Email addresses", 
#         "Passwords"
#       ], 
#       "Description": "In early 2013, <a href=\"https://staff.tumblr.com/post/144263069415/we-recently-learned-that-a-third-party-had\" target=\"_blank\" rel=\"noopener\">tumblr suffered a data breach</a> which resulted in the exposure of over 65 million accounts. The data was later put up for sale on a dark market website and included email addresses and passwords stored as salted SHA1 hashes.", 
#       "Domain": "tumblr.com", 
#       "IsFabricated": false, 
#       "IsRetired": false, 
#       "IsSensitive": false, 
#       "IsSpamList": false, 
#       "IsVerified": true, 
#       "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Tumblr.png", 
#       "ModifiedDate": "2016-05-29T22:59:04Z", 
#       "Name": "Tumblr", 
#       "PwnCount": 65469298, 
#       "Title": "tumblr"
#     }
#   ]
# }

template_json = {
  "Email": "brunojustin@gmail.com", 
  "Response": [
    {
      "AddedDate": "2019-02-25T08:35:58Z", 
      "BreachDate": "2018-12-01", 
      "DataClasses": [
        "Email addresses", 
        "Geographic locations", 
        "Names", 
        "Passwords", 
        "Phone numbers", 
        "Spoken languages", 
        "Usernames"
      ], 
      "Description": "In December 2018, the video messaging service <a href=\"https://www.theregister.co.uk/2019/02/11/620_million_hacked_accounts_dark_web/\" target=\"_blank\" rel=\"noopener\">Dubsmash suffered a data breach</a>. The incident exposed 162 million unique email addresses alongside usernames and PBKDF2 password hashes. In 2019, the data appeared listed for sale on a dark web marketplace (along with several other large breaches) and subsequently began circulating more broadly. The data was provided to HIBP by a source who requested it to be attributed to &quot;BenjaminBlue@exploit.im&quot;.", 
      "Domain": "dubsmash.com", 
      "IsFabricated": false, 
      "IsRetired": false, 
      "IsSensitive": false, 
      "IsSpamList": false, 
      "IsVerified": true, 
      "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Dubsmash.png", 
      "ModifiedDate": "2019-02-25T08:35:58Z", 
      "Name": "Dubsmash", 
      "PwnCount": 161749950, 
      "Title": "Dubsmash"
    }
  ]
}

r = requests.post('https://127.0.0.1:8080/report',data=json.dumps(template_json, ensure_ascii=False),verify=False)
with open('./metadata.pdf', 'wb') as f:
    print(r.content)
    f.write(r.content)

# a = generate_safe_pass('LarissaEPrado')