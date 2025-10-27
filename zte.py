import asyncio
import hashlib
import time
import httpx
import argparse
from typing import List, Dict, Any

class ZTEModem:
    def __init__(self, ip: str = "192.168.0.1", port: int = 80, password: str = "admin"):
        self.ip = ip
        self.port = port
        self.password = password
        self.session_cookie = None
        self.rd0 = None  # wa_inner_version
        self.rd1 = None  # cr_version
        self.base_url = f"http://{self.ip}:{self.port}" if port != 80 else f"http://{self.ip}"
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "X-Requested-With": "XMLHttpRequest",
            "Connection": "keep-alive",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache"
        }

    def _generate_timestamp(self) -> str:
        """Генерация timestamp для запросов"""
        return str(int(time.time() * 1000))

    def _generate_password_hash(self, password: str, ld: str) -> str:
        """Генерация хеша пароля по новому алгоритму"""
        # Первый SHA-256 по паролю, результат в HEX (строка длиной 64 символа)
        sha1 = hashlib.sha256(password.encode()).hexdigest().upper()

        # Конкатенация HEX-хеша и ld
        concat = sha1 + ld

        # Второй SHA-256 по строке
        final_hash = hashlib.sha256(concat.encode()).hexdigest().upper()

        return final_hash

    def _hex_md5(self, text: str) -> str:
        """MD5 хеш в hex формате"""
        return hashlib.md5(text.encode()).hexdigest()

    def _generate_ad_hash(self, rd_token: str) -> str:
        """Генерация AD хеша для операций: hex_md5(hex_md5(rd0 + rd1) + RD)"""
        if self.rd0 is None or self.rd1 is None:
            raise Exception("rd0 or rd1 not initialized. Call get_initial_data() first.")

        # Первый MD5: hex_md5(rd0 + rd1)
        first_hash = self._hex_md5(self.rd0 + self.rd1)
        print(f"First hash (rd0+rd1): {first_hash}")

        # Второй MD5: hex_md5(first_hash + RD)
        final_hash = self._hex_md5(first_hash + rd_token)
        print(f"Final AD hash: {final_hash}")

        return final_hash

    def _decode_hex_message(self, hex_text: str) -> str:
        """Декодирование SMS из HEX формата"""
        result = ''
        for i in range(0, len(hex_text), 4):
            try:
                result += chr(int(hex_text[i:i+4], 16))
            except ValueError:
                continue
        return result

    async def _get_ld_token(self) -> str:
        """Получение LD токена для аутентификации"""
        async with httpx.AsyncClient(timeout=10.0) as client:
            params = {
                "isTest": "false",
                "cmd": "LD",
                "_": self._generate_timestamp()
            }

            request_headers = self.headers.copy()
            request_headers["Referer"] = f"{self.base_url}/index.html"

            try:
                response = await client.get(
                    f"{self.base_url}/goform/goform_get_cmd_process",
                    params=params,
                    headers=request_headers
                )
                response.raise_for_status()

                data = response.json()
                ld_token = data.get('LD')

                if not ld_token:
                    raise Exception("LD token not found in response")

                print(f"Got LD token: {ld_token}")
                return ld_token

            except Exception as e:
                print(f"Error getting LD token: {e}")
                raise

    async def get_initial_data(self) -> bool:
        """Получение начальных данных (rd0, rd1) после логина"""
        if not self.session_cookie:
            print("Not authenticated")
            return False

        async with httpx.AsyncClient(timeout=10.0) as client:
            params = {
                "isTest": "false",
                "cmd": "Language,cr_version,wa_inner_version",
                "multi_data": "1",
                "_": self._generate_timestamp()
            }

            request_headers = self.headers.copy()
            request_headers["Referer"] = f"{self.base_url}/index.html"

            try:
                response = await client.get(
                    f"{self.base_url}/goform/goform_get_cmd_process",
                    params=params,
                    headers=request_headers,
                    cookies=self.session_cookie
                )
                response.raise_for_status()

                data = response.json()
                print(f"Initial data response: {data}")

                self.rd0 = data.get('wa_inner_version', '')
                self.rd1 = data.get('cr_version', '')

                print(f"rd0 (wa_inner_version): {self.rd0}")
                print(f"rd1 (cr_version): {self.rd1}")

                return True

            except Exception as e:
                print(f"Error getting initial data: {e}")
                return False

    async def _get_rd_token(self) -> str:
        """Получение RD токена для операций"""
        async with httpx.AsyncClient(timeout=10.0) as client:
            params = {
                "isTest": "false",
                "cmd": "RD",
                "_": self._generate_timestamp()
            }

            request_headers = self.headers.copy()
            request_headers["Referer"] = f"{self.base_url}/index.html"

            try:
                response = await client.get(
                    f"{self.base_url}/goform/goform_get_cmd_process",
                    params=params,
                    headers=request_headers,
                    cookies=self.session_cookie
                )
                response.raise_for_status()

                data = response.json()
                rd_token = data.get('RD')

                if not rd_token:
                    raise Exception("RD token not found in response")

                print(f"Got RD token: {rd_token}")
                return rd_token

            except Exception as e:
                print(f"Error getting RD token: {e}")
                raise

    async def authenticate(self) -> bool:
        """Аутентификация в модеме"""
        print(f"Connecting to {self.base_url}...")

        try:
            # Получаем LD токен
            ld_token = await self._get_ld_token()

            # Генерируем хеш пароля
            password_hash = self._generate_password_hash(self.password, ld_token)
            print(f"Generated password hash: {password_hash}")

            async with httpx.AsyncClient(timeout=10.0) as client:
                auth_data = {
                    'isTest': 'false',
                    'goformId': 'LOGIN',
                    'password': password_hash
                }

                auth_headers = self.headers.copy()
                auth_headers.update({
                    "Origin": self.base_url,
                    "Referer": f"{self.base_url}/index.html"
                })

                response = await client.post(
                    f"{self.base_url}/goform/goform_set_cmd_process",
                    data=auth_data,
                    headers=auth_headers
                )
                response.raise_for_status()

                result = response.json()
                print(f"Auth response: {result}")

                if result.get('result') != "0":
                    print(f"Auth failed: {result}")
                    return False

                # Ищем zsidn cookie
                zsidn_cookie = response.cookies.get("zsidn")
                if zsidn_cookie:
                    self.session_cookie = {"zsidn": zsidn_cookie}
                    print(f"Got zsidn cookie: {zsidn_cookie}")
                else:
                    # Fallback на старый stok cookie
                    stok_cookie = response.cookies.get("stok")
                    if stok_cookie:
                        self.session_cookie = {"stok": stok_cookie}
                        print(f"Got stok cookie: {stok_cookie}")
                    else:
                        print("No session cookie received")
                        return False

                # Получаем начальные данные после успешной аутентификации
                if not await self.get_initial_data():
                    print("Failed to get initial data")
                    return False

                print("Authentication successful")
                return True

        except httpx.ConnectError:
            print(f"Connection failed to {self.base_url}")
            return False
        except httpx.TimeoutException:
            print(f"Timeout connecting to {self.base_url}")
            return False
        except Exception as e:
            print(f"Authentication error: {e}")
            return False

    async def get_sms_list(self) -> List[Dict[str, Any]]:
        """Получение списка SMS"""
        if not self.session_cookie:
            print("Not authenticated")
            return []

        async with httpx.AsyncClient(timeout=10.0) as client:
            params = {
                "isTest": 'false',
                'cmd': 'sms_data_total',
                'page': '0',
                'data_per_page': '500',
                'mem_store': '1',
                'tags': '10',
                'order_by': 'order by id desc'
            }

            request_headers = self.headers.copy()
            request_headers["Referer"] = f"{self.base_url}/index.html"

            try:
                response = await client.get(
                    f"{self.base_url}/goform/goform_get_cmd_process",
                    params=params,
                    headers=request_headers,
                    cookies=self.session_cookie
                )
                response.raise_for_status()

                data = response.json()
                messages = data.get('messages', [])

                # Декодируем содержимое SMS
                decoded_messages = []
                for msg in messages:
                    if 'content' in msg:
                        msg['content'] = self._decode_hex_message(msg['content'])
                        msg['number'] = self._decode_hex_message(msg['number'])
                    decoded_messages.append(msg)

                return decoded_messages

            except Exception as e:
                print(f"Error getting SMS: {e}")
                return []

    async def delete_sms(self, msg_id: str) -> bool:
        """Удаление SMS по ID"""
        if not self.session_cookie:
            print("Not authenticated")
            return False

        try:
            # Получаем RD токен
            rd_token = await self._get_rd_token()

            # Генерируем AD хеш
            ad_hash = self._generate_ad_hash(rd_token)

            async with httpx.AsyncClient(timeout=10.0) as client:
                delete_data = {
                    'isTest': 'false',
                    'goformId': 'DELETE_SMS',
                    'msg_id': f'{msg_id};',  # Добавляем ; в конце
                    'notCallback': 'true',
                    'AD': ad_hash
                }

                delete_headers = self.headers.copy()
                delete_headers.update({
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Origin": self.base_url,
                    "Referer": f"{self.base_url}/index.html",
                    "Priority": "u=0"
                })

                response = await client.post(
                    f"{self.base_url}/goform/goform_set_cmd_process",
                    data=delete_data,
                    headers=delete_headers,
                    cookies=self.session_cookie
                )
                response.raise_for_status()

                result = response.json()
                print(f"Delete response: {result}")

                if result.get('result') == "success":
                    print(f"SMS {msg_id} deleted successfully")
                    return True
                else:
                    print(f"Failed to delete SMS {msg_id}: {result}")
                    return False

        except Exception as e:
            print(f"Error deleting SMS: {e}")
            return False

def parse_address(address: str) -> tuple[str, int]:
    """Парсинг адреса в формате ip:port или просто ip"""
    if ':' in address:
        ip, port_str = address.rsplit(':', 1)
        try:
            port = int(port_str)
            return ip, port
        except ValueError:
            raise ValueError(f"Invalid port in address: {address}")
    else:
        return address, 80

async def main():
    parser = argparse.ArgumentParser(description='ZTE Modem SMS Manager')
    parser.add_argument('--address', '-a',
                       default='192.168.0.1',
                       help='Modem address in format ip:port or just ip (default: 192.168.0.1)')
    parser.add_argument('--ip',
                       help='Modem IP address (alternative to --address)')
    parser.add_argument('--port', '-p',
                       type=int,
                       default=80,
                       help='Modem port (default: 80)')
    parser.add_argument('--password',
                       default='admin',
                       help='Modem password (default: admin)')
    parser.add_argument('--action',
                       choices=['list', 'delete'],
                       default='list',
                       help='Action to perform (default: list)')
    parser.add_argument('--msg-id',
                       help='SMS ID to delete (required for delete action)')
    parser.add_argument('--debug',
                       action='store_true',
                       help='Enable debug output')

    args = parser.parse_args()

    # Определяем IP и порт
    if args.ip:
        ip = args.ip
        port = args.port
    else:
        try:
            ip, port = parse_address(args.address)
        except ValueError as e:
            print(f"Error: {e}")
            return

    # Создаем экземпляр модема
    modem = ZTEModem(ip=ip, port=port, password=args.password)

    # Аутентификация
    if await modem.authenticate():
        if args.action == 'list':
            # Получаем SMS
            sms_list = await modem.get_sms_list()

            print(f"\nFound {len(sms_list)} SMS messages:")
            print("-" * 50)

            for i, sms in enumerate(sms_list, 1):
                print(f"SMS #{i} (ID: {sms.get('id', 'Unknown')}):")
                print(f"  From: {sms.get('number', 'Unknown')}")
                print(f"  Date: {sms.get('date', 'Unknown')}")
                print(f"  Content: {sms.get('content', 'Empty')}")
                print(f"  Status: {sms.get('tag', 'Unknown')}")
                print("-" * 30)

        elif args.action == 'delete':
            if not args.msg_id:
                print("Error: --msg-id is required for delete action")
                return

            success = await modem.delete_sms(args.msg_id)
            if success:
                print("SMS deleted successfully")
            else:
                print("Failed to delete SMS")
    else:
        print("Failed to authenticate")

if __name__ == "__main__":
    asyncio.run(main())
