import asyncio
import logging
import os
from typing import Set
from aiogram import Bot, Dispatcher
from aiogram.types import Message
from aiogram.filters import CommandStart
from zte import ZTEModem

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SMSRelayBot:
    def __init__(self, bot_token: str, target_user_id: int, modem_ip: str = "192.168.0.1", 
                 modem_port: int = 80, modem_password: str = "admin"):
        self.bot = Bot(token=bot_token)
        self.dp = Dispatcher()
        self.target_user_id = target_user_id
        self.modem = ZTEModem(ip=modem_ip, port=modem_port, password=modem_password)
        self.processed_sms_ids: Set[str] = set()
        self.setup_handlers()

    def setup_handlers(self):
        @self.dp.message(CommandStart())
        async def start_handler(message: Message):
            await message.answer("SMS Relay Bot запущен! Буду пересылать SMS с модема.")

    async def check_and_forward_sms(self):
        try:
            if not await self.modem.authenticate():
                logger.error("Не удалось авторизоваться в модеме")
                return

            sms_list = await self.modem.get_sms_list()
            
            for sms in sms_list:
                sms_id = sms.get('id')
                if sms_id not in self.processed_sms_ids:
                    content = sms.get('content', '')
                    sender = sms.get('number', 'Неизвестный')
                    date = sms.get('date', 'Неизвестная дата')
                    
                    message_text = f"📱 SMS от {sender}\n🕐 {date}\n\n{content}"
                    
                    await self.bot.send_message(
                        chat_id=self.target_user_id,
                        text=message_text
                    )
                    
                    self.processed_sms_ids.add(sms_id)
                    logger.info(f"Переслано SMS от {sender}: {content[:50]}...")
                    
                    await self.modem.delete_sms(sms_id)
                    logger.info(f"SMS {sms_id} удалено из модема")

        except Exception as e:
            logger.error(f"Ошибка при проверке SMS: {e}")

    async def periodic_sms_check(self):
        while True:
            await self.check_and_forward_sms()
            await asyncio.sleep(30)

    async def start(self):
        logger.info("Запуск SMS Relay Bot...")
        
        task1 = asyncio.create_task(self.dp.start_polling(self.bot))
        task2 = asyncio.create_task(self.periodic_sms_check())
        
        try:
            await asyncio.gather(task1, task2)
        finally:
            await self.bot.session.close()

def main():
    bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    target_user_id = os.getenv('TARGET_USER_ID')
    modem_ip = os.getenv('MODEM_IP', '192.168.0.1')
    modem_port = int(os.getenv('MODEM_PORT', '80'))
    modem_password = os.getenv('MODEM_PASSWORD', 'admin')
    
    if not bot_token:
        raise ValueError("TELEGRAM_BOT_TOKEN не установлен")
    if not target_user_id:
        raise ValueError("TARGET_USER_ID не установлен")
    
    try:
        target_user_id = int(target_user_id)
    except ValueError:
        raise ValueError("TARGET_USER_ID должен быть числом")
    
    bot = SMSRelayBot(
        bot_token=bot_token,
        target_user_id=target_user_id,
        modem_ip=modem_ip,
        modem_port=modem_port,
        modem_password=modem_password
    )
    
    asyncio.run(bot.start())

if __name__ == "__main__":
    main()