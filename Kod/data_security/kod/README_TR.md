# S-DES Veri Güvenliği Projesi

## Proje Açıklaması

Bu depo, **S-DES (Simplified Data Encryption Standard - Basitleştirilmiş Veri Şifreleme Standardı)** üzerine hazırlanmış bir üniversite Veri Güvenliği projesini içerir. Projede S-DES algoritmasının elle yazılmış Python uygulaması, Streamlit tabanlı etkileşimli bir web arayüzü, doğrulama testleri ve temel güvenlik analizi için yardımcı fonksiyonlar bulunmaktadır.

Projenin temel amacı S-DES algoritmasının bit düzeyinde nasıl çalıştığını göstermektir. Bu kapsamda anahtar üretimi, permütasyon işlemleri, şifreleme ve çözme turları, blok şifreleme kipleri, kaba kuvvet analizi ve diferansiyel kriptanaliz deneyleri ele alınmaktadır. Uygulama akademik inceleme ve sunum amacıyla hazırlanmıştır.

## Özellikler

- S-DES çekirdek algoritmasının elle uygulanması
- S-DES sabitleri ve permütasyon tabloları:
  - `P10`
  - `P8`
  - `P4`
  - `IP`
  - `IP^-1`
  - `EP`
- `S0` ve `S1` için S-kutusu tanımları
- İkili anahtarlar, bloklar ve başlangıç vektörleri için giriş doğrulama
- Düşük düzeyli bit işlemleri:
  - permütasyon
  - sola kaydırma
  - XOR
  - bölme ve birleştirme işlemleri
- Anahtar zamanlama ve alt anahtar üretimi:
  - `K1`
  - `K2`
- Tek blok şifreleme ve şifre çözme
- Blok şifreleme kipleri:
  - ECB
  - CBC
  - OFB
- Birden fazla etkileşimli sekmeye sahip Streamlit web arayüzü
- Adım adım şifreleme ve şifre çözme görselleştirmesi
- Bilinen açık metin ile kaba kuvvet saldırısı desteği
- Diferansiyel kriptanaliz yardımcı fonksiyonları
- S-kutusu fark dağılım tablosu üretimi
- Raporlamaya uygun doğrulama çıktıları
- Web arayüzünden indirilebilir metin çıktıları

## Kullanılan Teknolojiler

- S-DES çekirdek uygulaması için **Python**
- Etkileşimli web arayüzü için **Streamlit**
- Arayüzde tablo gösterimleri için **pandas**

Arka uçtaki S-DES mantığı elle uygulanmıştır ve S-DES çekirdek algoritması için hazır kriptografi kütüphanelerine dayanmaz.

## Hızlı Başlangıç

```bash
pip install streamlit pandas
streamlit run gui_app.py
```

Doğrulama betiğini çalıştırmak için:

```bash
python test_sdes_core.py
```

## Proje Yapısı

Proje üç temel Python dosyası etrafında düzenlenmiştir:

- `sdes_core.py` S-DES algoritmasını, blok şifreleme kiplerini, saldırı yardımcılarını ve diferansiyel kriptanaliz yardımcılarını içerir.
- `gui_app.py` etkileşimli gösterim için kullanılan Streamlit arayüzünü içerir.
- `test_sdes_core.py` doğrulama testlerini ve raporlamaya uygun çıktıları içerir.

## Depo Düzeni

```text
.
├── README.md
├── README_TR.md
├── gui_app.py
├── sdes_core.py
├── test_sdes_core.py
└── data_securityUML.drawio
```

## Gereksinimler / Ön Koşullar

Projeyi çalıştırmadan önce aşağıdakilerin kurulu olduğundan emin olunmalıdır:

- Python 3.x
- `pip`
- Streamlit
- pandas

Proje komut satırı üzerinden yerel olarak çalıştırılabilir. Bulut dağıtımı veya harici bir kriptografik servis gerektirmez.

## Kurulum

1. Depoyu klonlayın veya indirin.

2. Proje dizininde bir terminal açın.

3. Gerekli bağımlılıkları kurun:

```bash
pip install streamlit pandas
```

## Çalıştırma

### Streamlit Uygulamasını Çalıştırma

```bash
streamlit run gui_app.py
```

Bu komut çalıştırıldığında Streamlit yerel bir web sunucusu başlatır ve terminalde yerel bir URL verir.

### Test Betiğini Çalıştırma

```bash
python test_sdes_core.py
```

Test betiği beklenen değerleri, gerçek değerleri ve geçme/kalma sonuçlarını rapor veya proje gösteriminde kullanılabilecek bir biçimde yazdırır.

## Örnek Komutlar

```bash
# Bağımlılıkları kurma
pip install streamlit pandas

# Etkileşimli web arayüzünü başlatma
streamlit run gui_app.py

# Doğrulama ve gösterim testlerini çalıştırma
python test_sdes_core.py
```

## Kullanım

Streamlit arayüzü gösterim ve analiz amacıyla birkaç pratik bölüme ayrılmıştır.

### Encrypt / Decrypt Sekmesi

Bu sekme tek blok S-DES şifreleme ve şifre çözme işlemlerinin yapılmasını sağlar. Aşağıdaki bileşenleri içerir:

- 8 bit açık metin veya şifreli metin bloğu için giriş alanları
- 10 bit anahtar için giriş alanı
- üretilen `K1` ve `K2` alt anahtarları
- S-DES sürecinin adım adım görselleştirilmesi
- ara permütasyon, S-kutusu ve tur değerleri
- son şifreleme veya şifre çözme çıktısı

Bu bölüm, sunum sırasında S-DES'in iç yapısını açıklamak için uygundur.

### ECB / CBC / OFB Kip Sekmesi

Bu sekme yaygın blok şifreleme kipleriyle çok bloklu şifreleme ve şifre çözme işlemlerini destekler:

- **ECB (Electronic Codebook):** her bloğu bağımsız olarak işler
- **CBC (Cipher Block Chaining):** başlangıç vektörü ve bloklar arası zincirleme kullanır
- **OFB (Output Feedback):** şifre çıktısından geri besleme ile anahtar akışı üretir

Kullanıcılar birden fazla 8 bit blok girebilir, bir kip seçebilir, gerekli anahtarı ve gerektiğinde başlangıç vektörünü sağlayabilir ve oluşan blok çıktılarını görüntüleyebilir.

### Kaba Kuvvet Saldırısı Sekmesi

Bu sekme, küçük S-DES anahtar uzayına karşı bilinen açık metin ile kaba kuvvet analizini gösterir. Kullanıcılar açık metin ve şifreli metin çiftleri girerek aday 10 bit anahtarları arayabilir.

S-DES çok küçük bir anahtar boyutu kullandığı için tüm anahtarların denenmesi hesaplama açısından mümkündür ve eğitim amaçlı gösterim için uygundur.

### Diferansiyel Kriptanaliz Sekmesi

Bu sekme diferansiyel kriptanaliz deneyleri için yardımcı araçlar sunar:

- diferansiyel çift analizi
- diferansiyel deney çalıştırma
- S-kutusu fark dağılım tablosu üretimi

Bu araçlar, giriş farklarının basitleştirilmiş blok şifre bileşenlerinde çıkış farklarını nasıl etkileyebileceğini göstermeye yardımcı olur.

### Referans Tabloları

Arayüz ayrıca görünür S-DES referans bilgileri sunar:

- permütasyon tabloları
- genişletme/permütasyon tabloları
- S-kutusu tabloları

Bu tablolar adım adım öğrenmeyi destekler ve arayüzü sınıf içi gösterim için uygun hale getirir.

## Örnek Test Vektörleri

Doğrulama betiği, uygulamayı kontrol etmek için kullanılabilecek örnek S-DES tarzı test vektörleri içerir:

```text
Anahtar:       1010000010
Açık metin:    11010111
K1:            10100100
K2:            01000011
Şifreli metin: 10101000
```

Bu değerler `test_sdes_core.py` tarafından beklenen ve gerçek sonuçların karşılaştırılması için kullanılır. Ek örnekler Streamlit arayüzü üzerinden üretilebilir.

## Doğrulama ve Test

`test_sdes_core.py` dosyası uygulamanın önemli bölümlerini doğrular:

- giriş doğrulama kontrolleri
- yardımcı fonksiyon davranışları
- permütasyon işlemleri
- S-kutusu arama davranışı
- alt anahtar üretimi
- şifreleme ve şifre çözme doğruluğu
- diferansiyel kriptanaliz yardımcılarının davranışı
- gösterim amacıyla ayrıntılı şifre çözme izleme çıktısı

Betik sonuçları geçme/kalma biçiminde yazdırır; bu nedenle proje raporları ve canlı gösterimler için uygundur.

Testleri çalıştırmak için:

```bash
python test_sdes_core.py
```

## Güvenlik Analizi

Bu proje eğitim amacıyla temel güvenlik analizi özellikleri içerir.

### Kaba Kuvvet Analizi

S-DES 10 bit anahtar kullandığı için tüm anahtar uzayı yalnızca 1024 olası anahtardan oluşur. Projede, bilinen açık metin ve şifreli metin çiftlerini kullanarak bu anahtar uzayında arama yapabilen kaba kuvvet yardımcıları bulunmaktadır.

Bu durum, küçük anahtar boyutlarının neden güvensiz olduğunu ve modern kriptografik sistemlerin neden çok daha büyük anahtar uzaylarına ihtiyaç duyduğunu gösterir.

### Diferansiyel Kriptanaliz

Proje ayrıca S-kutusu fark dağılım tablosu üretimi ve diferansiyel çift deneyleri dahil olmak üzere diferansiyel kriptanaliz için yardımcı fonksiyonlar içerir.

Bu özellikler, giriş bloklarındaki farkların basitleştirilmiş şifre bileşenleri üzerinden nasıl yayıldığını kavramsal olarak incelemeyi desteklemek için tasarlanmıştır.

## Notlar / Sınırlamalar

- S-DES eğitim amaçlı bir algoritmadır ve gerçek dünya kullanımı için güvenli değildir.
- Uygulama öğrenme, test ve sunum amacıyla tasarlanmıştır.
- Proje hassas verileri korumak için kullanılmamalıdır.
- Streamlit arayüzü yerel gösterim amacıyla hazırlanmıştır.
- Kaba kuvvet ve diferansiyel kriptanaliz özellikleri akademik inceleme için basitleştirilmiştir.
- Uygulama endüstriyel performanstan çok açıklık ve izlenebilirlik üzerine odaklanır.

## İsteğe Bağlı Gelecek Geliştirmeler

Gelecekte yapılabilecek olası geliştirmeler şunlardır:

- daha fazla önceden tanımlanmış test vektörü eklemek
- tam adım adım izleri yapılandırılmış rapor dosyaları olarak dışa aktarmak
- Feistel turları için görsel diyagramlar eklemek
- çok bloklu giriş biçimlendirme seçeneklerini geliştirmek
- diferansiyel kriptanaliz çıktıları için daha ayrıntılı açıklamalar eklemek
- ECB, CBC ve OFB kipleri için otomatik testleri genişletmek

## Lisans

Akademik kullanım içindir.

## Yazarlar

- Öğrenci Adı 1
- Öğrenci Adı 2
- Öğrenci Adı 3

