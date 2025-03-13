import telebot
from telebot import types
from utils.report_generator import ReportGenerator
import os

class ReportHandler:
    def __init__(self, bot: telebot.TeleBot, config):
        """
        Initialise le gestionnaire de rapports pour le bot Telegram.
        
        :param bot: Instance du bot Telegram
        :param config: Configuration du bot
        """
        self.bot = bot
        self.config = config
        
    def handle_report_command(self, message: types.Message):
        """
        Gère la commande de génération de rapport.
        
        :param message: Message Telegram déclenchant la commande
        """
        user_id = str(message.from_user.id)
        
        # Vérifier si des analyses précédentes existent
        report_generator = ReportGenerator(user_id)
        
        try:
            # Charger les données des scans précédents
            report_data = report_generator.generate_report()
            
            # Chemins des fichiers de rapport
            html_path = os.path.join(report_generator.cache_dir, f'{user_id}_report.html')
            pdf_path = os.path.join(report_generator.cache_dir, f'{user_id}_report.pdf')
            
            # Créer un clavier inline pour les options de rapport
            markup = types.InlineKeyboardMarkup()
            html_button = types.InlineKeyboardButton(
                "Voir le Rapport HTML", 
                callback_data=f'view_report_html_{user_id}'
            )
            pdf_button = types.InlineKeyboardButton(
                "Télécharger PDF", 
                callback_data=f'download_report_pdf_{user_id}'
            )
            markup.row(html_button, pdf_button)
            
            # Envoyer un message récapitulatif
            risk_summary = f"🚨 Niveau de Risque Global : {report_data['overall_risk']}\n\n"
            risk_summary += "Voici un aperçu rapide de vos résultats de sécurité :\n"
            
            # Ajouter des détails par catégorie
            if report_data.get('breach_data', {}).get('breaches'):
                risk_summary += f"📊 Fuites de Données : {report_data['risk_scores']['breach']}/10\n"
            
            if report_data.get('url_scan_data'):
                risk_summary += f"🌐 Analyse URL : {report_data['risk_scores']['url']}/10\n"
            
            if report_data.get('darkweb_data', {}).get('mentions'):
                risk_summary += f"🕵️ Surveillance Darkweb : {report_data['risk_scores']['darkweb']}/10\n"
            
            if report_data.get('vuln_scan_data', {}).get('vulnerabilities'):
                risk_summary += f"🛡️ Vulnérabilités : {report_data['risk_scores']['vuln']}/10\n"
            
            if report_data.get('password_check_data'):
                risk_summary += f"🔐 Sécurité Mot de Passe : {report_data['risk_scores']['password']}/10\n"
            
            self.bot.reply_to(
                message, 
                risk_summary, 
                reply_markup=markup
            )
        
        except Exception as e:
            # Gestion des erreurs
            error_msg = f"Impossible de générer le rapport : {str(e)}"
            self.bot.reply_to(message, error_msg)
    
    def handle_report_callback(self, call: types.CallbackQuery):
        """
        Gère les interactions avec les boutons du rapport.
        
        :param call: Callback de l'interaction Telegram
        """
        try:
            # Extraire l'action et l'ID utilisateur
            data_parts = call.data.split('_')
            action = data_parts[1]  # 'view' ou 'download'
            report_type = data_parts[2]  # 'html' ou 'pdf'
            user_id = data_parts[3]
            
            # Chemins des fichiers
            cache_dir = 'reports_cache'
            file_path = os.path.join(cache_dir, f'{user_id}_report.{report_type}')
            
            if action == 'view' and report_type == 'html':
                # Envoyer le contenu HTML
                with open(file_path, 'r') as f:
                    html_content = f.read()
                
                # Limiter la taille du message
                if len(html_content) > 4096:
                    html_content = html_content[:4096] + "... (contenu tronqué)"
                
                self.bot.answer_callback_query(
                    call.id, 
                    text="Aperçu du rapport HTML"
                )
                self.bot.send_message(
                    call.message.chat.id, 
                    f"```html\n{html_content}\n```", 
                    parse_mode='Markdown'
                )
            
            elif action == 'download' and report_type == 'pdf':
                # Envoyer le fichier PDF
                with open(file_path, 'rb') as pdf_file:
                    self.bot.send_document(
                        call.message.chat.id, 
                        pdf_file, 
                        caption="Votre rapport de sécurité BreacheRadar"
                    )
                
                self.bot.answer_callback_query(
                    call.id, 
                    text="Téléchargement du rapport PDF"
                )
        
        except FileNotFoundError:
            self.bot.answer_callback_query(
                call.id, 
                text="Désolé, le rapport n'a pas été trouvé."
            )
        except Exception as e:
            self.bot.answer_callback_query(
                call.id, 
                text=f"Erreur : {str(e)}"
            )

# Exemple d'intégration dans le bot principal
def setup_report_handlers(bot, config):
    """
    Configure les gestionnaires de rapports dans le bot Telegram.
    
    :param bot: Instance du bot Telegram
    :param config: Configuration du bot
    """
    report_handler = ReportHandler(bot, config)
    
    # Gestionnaire de commande pour générer un rapport
    @bot.message_handler(commands=['report'])
    def handle_report_command(message):
        report_handler.handle_report_command(message)
    
    # Gestionnaire de callback pour les interactions de rapport
    @bot.callback_query_handler(func=lambda call: call.data.startswith('view_report_') or call.data.startswith('download_report_'))
    def handle_report_callback(call):
        report_handler.handle_report_callback(call)

# Code de test/exemple
if __name__ == '__main__':
    # Configuration de test
    config = {
        'telegram_token': 'YOUR_BOT_TOKEN'
    }
    
    # Initialisation du bot (à adapter à votre configuration)
    bot = telebot.TeleBot(config['telegram_token'])
    
    # Configuration des gestionnaires de rapport
    setup_report_handlers(bot, config)
    
    # Démarrer le bot
    print("Bot en cours d'exécution...")
    bot.polling()