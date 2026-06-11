# linux-log-analyzer

`linux-log-analyzer`, Fedora 42+ ve modern Linux sistemlerde kimlik doğrulama loglarını güvenlik odaklı incelemek için geliştirilmiş Python tabanlı bir CLI aracıdır.

Bu projeyi sistem yönetimi ve siber güvenlik log analizi pratiği yapmak, SSH/sudo aktivitelerini daha anlaşılır raporlamak ve Linux güvenlik olaylarını modüler bir analiz motoruyla değerlendirmek için geliştiriyorum.

## Neden Bu Proje?

Linux sistemlerde güvenlik olayları genellikle `/var/log/secure`, eski dağıtımlarda `auth.log` veya `journalctl` çıktıları içinde dağınık şekilde bulunur. Bu proje, bu kayıtları tek bir CLI üzerinden parse ederek:

- başarısız SSH girişlerini,
- root login denemelerini,
- sudo kullanımını,
- invalid user denemelerini,
- IP bazlı şüpheli hareketleri,
- genel risk skorunu

daha okunabilir ve raporlanabilir hale getirir.

## Özellikler

- Dosyadan log analizi: `--file`
- Fedora/systemd journal analizi: `--journal`
- `journalctl --since` ve `--unit` filtre desteği
- SSH failed login tespiti
- SSH successful login tespiti
- Root login denemesi tespiti
- Invalid user enumeration tespiti
- Sudo komutu kullanım tespiti
- Brute-force kuralı: aynı IP'den 5+ failed password
- Severity sıralaması: `HIGH > MEDIUM > LOW > INFO`
- 0-100 arası risk skoru
- Parse edilemeyen satır sayısını özet raporda gösterme
- IP bazlı özet: toplam, failed, accepted, root ve invalid user sayaçları
- Terminal, JSON ve TXT rapor formatları
- Raporu dosyaya kaydetme
- Test edilebilir modüler mimari
- Python standart kütüphanesiyle minimum bağımlılık

## Desteklenen Log Türleri

Şu an desteklenen olay örnekleri:

```text
May 26 12:44:03 fedora sshd[1423]: Failed password for invalid user admin from 192.168.1.50 port 55322 ssh2
May 26 12:45:10 fedora sshd[1423]: Accepted password for orucreis from 192.168.1.20 port 49812 ssh2
May 26 12:46:01 fedora sudo: orucreis : TTY=pts/0 ; PWD=/home/orucreis ; USER=root ; COMMAND=/usr/bin/dnf update
May 26 12:47:33 fedora sshd[1500]: Failed password for root from 203.0.113.10 port 41231 ssh2
```

Pratikte hedeflenen kaynaklar:

- Fedora/RHEL ailesi: `/var/log/secure`
- Debian/Ubuntu ailesi: `/var/log/auth.log`
- systemd journal çıktısı: `journalctl`
- Dosyaya aktarılmış journal çıktıları

## Kurulum

Python 3.11+ gereklidir.

```bash
git clone https://github.com/orucreis04/linux-log-analyzer.git
cd linux-log-analyzer

python -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e .
```

Runtime bağımlılığı yoktur; proje şu an yalnızca Python standart kütüphanesini kullanır.

Geliştirme ve test için:

```bash
python -m pip install -e ".[dev]"
```

## Fedora 42+ Üzerinde Kullanım

Dosya üzerinden analiz:

```bash
python main.py --file /var/log/secure --format table
```

Son bir saatin journal kayıtlarını analiz etme:

```bash
python main.py --journal --since "1 hour ago"
```

Sadece SSH servisine ait kayıtları analiz etme:

```bash
python main.py --journal --unit sshd --since today
```

Journal kayıtlarına erişim sistem yetkilerine bağlıdır. Kullanıcı hesabınız journal okuma yetkisine sahip değilse komutu `sudo` ile çalıştırmanız veya kullanıcıyı uygun systemd journal grubuna eklemeniz gerekebilir.

## Örnek Komutlar

Terminal tablo çıktısı:

```bash
python main.py --file tests/sample_logs/auth_sample.log --format table
```

JSON rapor kaydetme:

```bash
python main.py --file tests/sample_logs/auth_sample.log --format json --output reports/report.json
```

TXT rapor kaydetme:

```bash
python main.py --file tests/sample_logs/auth_sample.log --format txt --output reports/report.txt
```

CLI yardım ekranı:

```bash
python main.py --help
```

## Örnek Çıktı

```text
Linux Log Analyzer Summary
Total Events: 4
Unparsed Lines: 1
Findings: 2
Risk Score: 17/100

severity | rule               | title                       | ip           | user     | count
---------+--------------------+-----------------------------+--------------+----------+------
MEDIUM   | ROOT_LOGIN_ATTEMPT | Root Login Attempt Detected | 203.0.113.10 | root     | 1
INFO     | SUDO_USAGE         | Sudo Command Executed       | -            | orucreis | 1

Top Source IPs
192.168.1.20 | total=1 | accepted=1
192.168.1.50 | total=1 | failed=1 | invalid_user=1
203.0.113.10 | total=1 | root=1
```

## JSON Rapor Örneği

```json
{
  "summary": {
    "total_events": 4,
    "unparsed_lines": 1,
    "total_findings": 2,
    "high_count": 0,
    "medium_count": 1,
    "low_count": 0,
    "info_count": 1,
    "risk_score": 17
  },
  "findings": [
    {
      "rule_id": "ROOT_LOGIN_ATTEMPT",
      "title": "Root Login Attempt Detected",
      "severity": "MEDIUM",
      "description": "A failed SSH password attempt targeted the root account.",
      "source_ip": "203.0.113.10",
      "username": "root",
      "evidence_count": 1,
      "recommendation": "Disable direct root SSH login and require privileged access through sudo."
    }
  ],
  "top_source_ips": [
    {
      "source_ip": "192.168.1.50",
      "total_events": 1,
      "failed_login_count": 1,
      "accepted_login_count": 0,
      "root_attempt_count": 0,
      "invalid_user_attempt_count": 1
    }
  ]
}
```

## Proje Klasör Yapısı

```text
linux-log-analyzer/
├── linux_log_analyzer/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── cli.py
│   ├── models.py
│   ├── parser.py
│   ├── report.py
│   ├── rules.py
│   └── utils.py
├── tests/
│   ├── sample_logs/
│   │   └── auth_sample.log
│   ├── test_analyzer.py
│   ├── test_cli.py
│   ├── test_parser.py
│   ├── test_report.py
│   └── test_utils.py
├── LICENSE
├── README.md
├── main.py
├── pyproject.toml
└── requirements.txt
```

## Test Çalıştırma

```bash
python -m pytest
```

Test kapsamı:

- log satırı parse etme
- analiz kuralları
- risk skoru
- IP bazlı istatistik
- rapor formatları
- CLI kaynak doğrulama
- `journalctl` subprocess davranışı

## Yol Haritası

- Zaman penceresi bazlı brute-force analizi
- IPv6 desteği
- CIDR/subnet bazlı IP gruplama
- GeoIP entegrasyonu
- YAML/JSON kural konfigürasyonu
- CSV rapor formatı
- HTML rapor formatı
- Daha fazla servis desteği: `su`, `polkit`, `firewalld`
- Paketlenmiş CLI dağıtımı ve GitHub Actions CI

## Güvenlik Notu

Bu araç savunma amaçlı log analizi ve sistem yönetimi pratiği için tasarlanmıştır. Üretilen bulgular otomatik karar yerine önceliklendirme ve inceleme desteği olarak değerlendirilmelidir. Gerçek sistemlerde IP engelleme, kullanıcı kilitleme veya erişim politikası değişikliği yapmadan önce log kaynağı, zaman aralığı ve olay bağlamı doğrulanmalıdır.

Log dosyaları kullanıcı adları, IP adresleri ve komut geçmişi gibi hassas bilgiler içerebilir. Raporları paylaşmadan önce gizli bilgileri maskeleyin.

## Lisans Bilgisi

Bu proje MIT lisansı ile yayınlanmıştır. Ayrıntılar için [LICENSE](LICENSE) dosyasına bakın.

## Örnek Geliştirme Planı

Bu proje için kısa vadeli geliştirme planı:

1. Zaman penceresi bazlı brute-force tespiti eklemek.
2. IPv6 ve subnet/CIDR bazlı IP gruplama desteği geliştirmek.
3. Kural eşiklerini YAML veya JSON konfigürasyonuyla yönetilebilir hale getirmek.
4. CSV ve HTML rapor formatları eklemek.
5. GitHub Actions ile otomatik test pipeline'ı kurmak.
6. Fedora üzerinde gerçek `/var/log/secure` ve `journalctl` örnekleriyle daha geniş test verisi oluşturmak.
7. `su`, `polkit` ve `firewalld` gibi ek servis loglarını desteklemek.
