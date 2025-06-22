import requests

# Введите ваш API-ключ сюда
API_KEY = 'ваш_ключ_здесь'

# Заголовки для авторизации
headers = {
    "x-apikey": API_KEY
}

def scan_url(url):
    """
    Отправляет URL на проверку в VirusTotal.
    """
    scan_url_endpoint = 'https://www.virustotal.com/api/v3/urls'
    # Кодируем URL в base64 (без знаков '=')
    import base64
    url_bytes = url.encode()
    url_b64 = base64.urlsafe_b64encode(url_bytes).decode().strip("=")
    
    data = {'url': url}
    
    response = requests.post(scan_url_endpoint, headers=headers, data=data)
    
    if response.status_code == 200:
        json_response = response.json()
        url_id = json_response['data']['id']
        print(f"URL отправлен на проверку. ID: {url_id}")
        return url_id
    else:
        print(f"Ошибка при отправке URL: {response.status_code}")
        print(response.text)

def get_url_report(url_id):
    """
    Получает отчет по проверке URL.
    """
    report_endpoint = f'https://www.virustotal.com/api/v3/analyses/{url_id}'
    
    response = requests.get(report_endpoint, headers=headers)
    
    if response.status_code == 200:
        report = response.json()
        print("Отчет по URL:")
        print(report)
    else:
        print(f"Ошибка при получении отчета: {response.status_code}")
        print(response.text)

def main():
    url_to_check = input("Введите URL для проверки: ")
    
    # Отправляем URL
    url_id = scan_url(url_to_check)
    
    if url_id:
        import time
        print("Ожидание обработки анализа...")
        time.sleep(15)  # подождать некоторое время перед получением отчета
        
        # Получаем отчет
        get_url_report(url_id)

if __name__ == "__main__":
    main()
