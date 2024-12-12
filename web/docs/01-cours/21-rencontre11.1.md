---
id: r21
title: Rencontre 21 - Sécuriser une application
sidebar_label: R21 - Sécuriser une application
draft: true
hide_table_of_contents: false
---

Nous allons explorer l'application fournie pour le cours:
- l'application se trouve dans le repo du cours https://github.com/departement-info-cem/3U4-cybersec



Dans les 4 prochaines semaines, nous allons voir comment on peut attaquer un système puis le défendre sur 3 aspects:
- le cassage d'un mot de passe sur une BD fuitée
- le cassage d'une encryption sur une BD fuitée
- l'injection SQL sur l'application (sans BD fuitée)

## Exercice / activité: se familiariser avec l'application

Pour le TP3, vous devrez remettre plusieurs éléments:
- une application corrigée dans le repo Github classroom
- des documents en format MarkDown sur les failles / exploit / correctifs découverts

On peut donc commencer par télécharger l'application et la placer dans votre repo du TP.

Ensuite, vous allez l'ouvrir dans VisualStudio, la lancer et vous familiariser avec son utilisation.

## Activité manuel: 

Pour l'instant l'application n'a pas de manuel d'instruction. Pour ton utilisation future, on veut que tu documentes les 
opérations principales permises par l'application:
- faire gna TODO
- faire pipo TODO

## Lecture du code:

La plupart des correctifs que tu vas appliquer nécessite de modifier le code de l'application. 
Cela vaut donc la peine de passer à travers le code. 

La méthode que nous recommandons est la suivante:
- place un certain nombres de point d'arrêt dans l'application
- note dans un fichier **tracemanuelle.md** par où tu penses que l'exécution va passer pour mettons créer un compte 
dans le format nomfichier ligne. Par exemple:
```text
fichier1.cs ligne 10
fichier2.cs ligne 7
fichier1.cs ligne 15
fichier3.cs ligne 25
```
- valide en effectuant l'opération sur l'application partie en débogage


