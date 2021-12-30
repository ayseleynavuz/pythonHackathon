import hashlib as hasher
import math
from Cryptodome.Cipher import AES,DES
from Cryptodome.Random import get_random_bytes
from secrets import token_bytes

class sifrelemeYontemleri:#sha1(), sha224(), sha256(), sha384(), sha512(),DES(),AES(),md5() şifreleme yöntemlerinin bulunduğu sınıf.
                
    def __init__(self):
        self.key = get_random_bytes(16)
        self.key2=token_bytes(8)
    def sha256Hash(self,value):
        try:
            if not value:
                raise ValueError("Value parametresi içersinde veri bulunmamaktadır.")
            else:
                return hasher.sha256(value.encode('utf-8')).hexdigest()
        except ValueError as e:
            print(e)

        

    def md5Hash(self,value): 
        return hasher.md5(value.encode('utf-8')).hexdigest()

    def Sha1Hash(self,value):
        return hasher.sha1(value.encode('utf-8')).hexdigest()

    def sha224Hash(self,value): 
        return hasher.sha224(value.encode('utf-8')).hexdigest()

    def sha384Hash(self,value):
        return hasher.sha384(value.encode('utf-8')).hexdigest()

    def sha512Hash(self,value): 
        return hasher.sha512(value.encode('utf-8')).hexdigest()

    def AesHash(self,data):
        
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)  
        return ciphertext
        #[ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
        #file_out.close()

    def DesHash(self,data):
        cipher = DES.new(self.key2, DES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data.encode('ascii'))
        return ciphertext


class dilKontrol: # Klavyeden girilen metnin cümle,kelime,sesli harf sayısının döndürüldüğü ve büyük ünlü uyumu kontrolünün yapıldığı sınıf.
    metin=""
    kalinHarfler="AIOUaıou"
    inceHarfler="EİÖÜeiöü"
    sesliHarfler = 'AIOUaıouEİÖÜeiöü'
    sesliHarfSayi=0
    kontrolKalin=False
    kontrolInce=False
    buyukUnluUyumuSayi=0
    notBuyukUnluUyumuSayi=0
    kelimeler=[]
    cumleler=[]
    def __init__(self,metin):
        self.metin=metin

    def cumleBul(self,metin): #Metni Cumlelere ayıran fonksiyon
        metin=metin.strip(".?")
        self.cumleler=metin.split(".")
        return self.cumleler

    def cumleSayi(self,cumle): #Cumle adedi bulan fonksiyon
        return len(cumle)

    def kelimeBul(self,cumle): #Cumleleri kelimelere ayıran fonksiyon
        for i in range (len(cumle)):
             self.kelimeler.extend(cumle[i].split())
        return self.kelimeler

    def kelimeSayi(self,kelime): #Kelime adedi bulan fonksiyon
        return len(kelime)

    def sesliHarfBul(self,metin): #Sesli harf adedi bulan fonksiyon
        self.sesliHarfSayi=0
        for metinHarf in metin:
            if metinHarf in self.sesliHarfler:
                self.sesliHarfSayi+=1
        return self.sesliHarfSayi
    
    def buyukUnluUyumuKontrol(self,kelimeler): #Büyük ünlü uyumu kontrolünün yapıldığı fonksiyon
        for i in range(len(kelimeler)):
            self.kontrolInce=False
            self.kontrolKalin=False
            if(self.sesliHarfBul(kelimeler[i])!=1):
                for j in kelimeler[i]:
                    if j in self.kalinHarfler:
                        self.kontrolKalin=True
                    if j in self.inceHarfler:
                        self.kontrolInce=True
                if (self.kontrolInce and self.kontrolKalin)==False:
                    self.buyukUnluUyumuSayi+=1
                else:
                    self.notBuyukUnluUyumuSayi+=1
            else:    
                self.notBuyukUnluUyumuSayi+=1
        
        return self.buyukUnluUyumuSayi,self.notBuyukUnluUyumuSayi
                    


class help: # Modulu ve içerisindeki classları açıklayan class.
    sifrelemeYontemleriHelp=""
    dilKontrolHelp=""

    def __init__(self):
        dosya1 = open("dilKontrolHelp.txt","r",encoding="utf-8")
        dosya2 = open("sifrelemeYontemleriHelp.txt","r",encoding="utf-8")
        self.dilKontrolHelp = dosya1.read()
        self.sifrelemeYontemleriHelp=dosya2.read()
        self.helpYazdir()

    def helpYazdir(self):
        print (self.sifrelemeYontemleriHelp)
        print()
        print (self.dilKontrolHelp)

def main():
        sayilar="0123456789"
        kontrol=False
        try:
            metin=input("Lütfen metni giriniz : ")
            for i in metin:
                if i in sayilar:
                    kontrol=True
            if kontrol==True:
                raise ValueError("Sayısal veri Hatasi ! Lütfen sadece harfler ile metin oluşturun !")
            else:
                erisim=dilKontrol(metin)
                cumleler=erisim.cumleBul(erisim.metin)

                cumleSayi=erisim.cumleSayi(cumleler)
                print("Cümle sayısı : {}".format(cumleSayi))

                kelimeler=erisim.kelimeBul(cumleler)
                kelimeSayi=erisim.kelimeSayi(kelimeler)
                print("Kelime sayısı : {}".format(kelimeSayi))

                sesliHarfSayi=erisim.sesliHarfBul(metin)
                print("Sesli harf sayısı : {}".format(sesliHarfSayi))

                buyukUnluUyumu=erisim.buyukUnluUyumuKontrol(kelimeler)
                print("Büyük ünlü uymuna uyan kelime sayısı : {}".format(buyukUnluUyumu[0]))
                print("Büyük ünlü uyumuna uymayan kelime sayısı :{}".format(buyukUnluUyumu[1]))
        except ValueError as e:
            print(e)
        help() 