##  **ROADMAP ASM pour PWN**

### **Phase 1: Les Bases (Semaine 1-2)**

#### 1. **Théorie interactive**
- **[CPU Simulator](https://cpu.land/)** - Comprendre comment le CPU exécute le code
- **[Teach Yourself Assembly](https://www.cs.virginia.edu/~evans/cs216/guides/x86.html)** - Guide x86-64 complet
- **[x86 Assembly Guide](https://www.cs.yale.edu/flint/cs421/papers/x86-asm/asm.html)** - Yale University

#### 2. **Pratique guidée**
- **[PC Assembly Book](https://pacman128.github.io/pcasm/)** - Livre gratuit avec exercices
- **[Programming from the Ground Up](https://savannah.nongnu.org/projects/pgubook/)** - Utilise ASM Linux

### **Phase 2: Pratique Intensive (Semaine 3-4)**

#### 3. **Défis interactifs**
- **[https://asmtutor.com/](https://asmtutor.com/)** - Tutoriels pas à pas
- **[MIPS Assembly](https://www.mycompiler.io/new/asm-x86_64)** - Compilateur en ligne pour tester
- **[x86-64 Assembly](https://www.tutorialspoint.com/assembly_programming/index.htm)** - Cours complet

#### 4. **Exercices progressifs**
```bash
# Installation des outils nécessaires
sudo apt-get install nasm gdb gcc make
```

- **[https://asmschool.github.io/](https://asmschool.github.io/)** - Exercices du plus simple au complexe
- **[https://github.com/0xAX/asm](https://github.com/0xAX/asm)** - 70+ exemples commentés

### **Phase 3: Pwn Spécifique (Semaine 5-6)**

#### 5. **Reverse Engineering débutant**
- **[https://crackmes.one/](https://crackmes.one/)** - Commence par "easy" avec ASM
- **[https://pwnable.tw/](https://pwnable.tw/)** - Défis avec writeups
- **[https://pwnable.xyz/](https://pwnable.xyz/)** - Interface interactive

#### 6. **Comprendre le binaire**
- **[https://github.com/RPISEC/MBE](https://github.com/RPISEC/MBE)** - Modern Binary Exploitation
- **[https://guyinatuxedo.github.io/](https://guyinatuxedo.github.io/)** - Nightmare: cours d'exploitation

### **Phase 4: Maîtrise (Semaine 7-8+)**

#### 7. **CTF Platforms**
- **[https://picoctf.org/](https://picoctf.org/)** - Commence ici (très pédagogique)
- **[https://ropemporium.com/](https://ropemporium.com/)** - Le site ULTIME pour ROP
- **[https://microcorruption.com/](https://microcorruption.com/)** - Debugging interactif

#### 8. **Défis avancés**
- **[https://exploit.education/](https://exploit.education/)** - Phoenix, Nebula, Fusion
- **[https://www.vulnhub.com/](https://www.vulnhub.com/)** - Machines virtuelles
- **[https://hackthebox.com/](https://hackthebox.com/)** - Machines challenges

## 📖 **RESSOURCES OFFICIELLES PAR ARCHITECTURE**

### **Intel x86/x64 (le plus important pour pwn)**
- **[Intel Manuals](https://software.intel.com/content/www/us/en/develop/articles/intel-sdm.html)** - Les vrais manuels (Volume 2 = instructions)
- **[AMD Manuals](https://developer.amd.com/resources/developer-guides-manuals/)** - Alternative

### **ARM (mobile, IoT)**
- **[ARM Architecture Manuals](https://developer.arm.com/architectures/cpu-architecture)** - Officiel
- **[ARM Assembly Basics](https://azeria-labs.com/writing-arm-assembly-part-1/)** - Azeria Labs (excellent)

##  **OUTILS INDISPENSABLES**

### **Debuggers**
```bash
# GDB avec extensions
sudo apt-get install gdb
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh

# Alternative
git clone https://github.com/hugsy/gef
```

### **Désassembleurs**
- **[Ghidra](https://ghidra-sre.org/)** - Gratuit, très puissant
- **[IDA Pro Free](https://hex-rays.com/ida-free/)** - Version gratuite limitée
- **[Binary Ninja Demo](https://binary.ninja/demo/)** - Version web

### **Visualisation**
- **[Compiler Explorer](https://godbolt.org/)** - Voir C → ASM en direct
- **[Python Tutor](https://pythontutor.com/)** - Visualise l'exécution

## **PROJETS PRATIQUES**

### **Niveau 1: Écris ces programmes en ASM**
1. Hello World
2. Addition de deux nombres
3. Boucle for/while
4. Fonction avec paramètres

### **Niveau 2: Reverse ces programmes**
1. Trouve le mot de passe dans un binaire
2. Patch un binaire pour changer le comportement
3. Crée un keygen

### **Niveau 3: Exploitation**
1. Buffer overflow simple
2. Format string leak
3. ROP chain basique

##  **LIVRES GRATUITS**

- **[The Art of Assembly Language](https://www.ic.unicamp.br/~pannain/mc404/aulas/pdfs/Art%20Of%20Intel%20x86%20Assembly.pdf)**
- **[x86-64 Assembly Programming](https://github.com/0xAX/asm/blob/master/asm_64.pdf)**
- **[Reverse Engineering for Beginners](https://beginners.re/)** - EN + RU

## **COMMUNAUTÉS POUR AIDE**

- **[Reddit r/ReverseEngineering](https://reddit.com/r/ReverseEngineering)**
- **[Reddit r/asm](https://reddit.com/r/asm)**
- **[Stack Overflow Assembly Tag](https://stackoverflow.com/questions/tagged/assembly)**
- **[Discord: Pwnland](https://discord.gg/pwnland)** (serveur pwn francophone)

## **TRUCS POUR ACCÉLÉRER**

### **Méthode "Just In Time"**
Quand tu vois une instruction inconnue :
```bash
# Dans gdb
help x
help i

# En ligne
https://www.felixcloutier.com/x86/  # Toutes les instructions x86
```

### **Méthode "Compare and Contrast"**
```c
// Écris du C, regarde l'ASM
int a = 5;
int b = a + 3;
```

### **Méthode "Step by Step"**
```bash
gdb ./program
break main
run
stepi  # exécute instruction par instruction
info registers
x/10x $rsp
```

## **Conseil final :**

Commence par **https://picoctf.org/** (c'est fait pour les débutants) et **https://ropemporium.com/** (quand tu seras prêt pour le pwn).

N'essaie pas de tout apprendre d'un coup. L'ASM s'apprend en **pratiquant** pas en lisant. Chaque jour, écris ou reverse un petit programme !

