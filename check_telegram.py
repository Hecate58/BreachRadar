import sys
print(f"Version Python: {sys.version}")
print(f"Chemin d'exécution Python: {sys.executable}")
print(f"Chemins de recherche des modules: {sys.path}")

try:
    import telegram
    print(f"Module telegram trouvé et importé avec succès. Version: {telegram.__version__}")
except ImportError as e:
    print(f"Erreur lors de l'importation du module telegram: {e}")
    print("Vérification des packages installés...")
    
    import subprocess
    result = subprocess.run([sys.executable, "-m", "pip", "list"], capture_output=True, text=True)
    print("Packages installés:")
    for line in result.stdout.split('\n'):
        if 'telegram' in line.lower():
            print(f"  {line}")
            