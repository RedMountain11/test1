#!/usr/bin/python3

from tkinter import *
from tkinter.messagebox import *
import subprocess
import os
import sys
import random
import time


#  №№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№ Первая функция - рисует меню. Все следующие рисуют и управляют всем, что внутри меню и в глубине их. №№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№

def makemenu(root):
    top = Menu(root)
    root.config(menu=top)
    file = Menu(top, tearoff=False)
    file.add_command(label="Настройки подписи", command=make_settings_sign)
    file.add_command(label="Настройки шифрования", command=make_settings_enc)
    file.add_command(label="Доступные сертификаты", command=make_see_cert)
    file.add_command(label='Выход', command=root.quit, underline=0)
    top.add_cascade(label='Настройки', menu=file, underline=0)

    service_menu = Menu(top, tearoff=False)
    service_menu.add_command(label="Операции с контейнерами и сертификатами", command=make_service_menu)
    top.add_cascade(label="Сервис криптопровайдера", menu=service_menu, underline=0)

    dop = Menu(top, tearoff=False)
    dop.add_command(label="Случайная мудрость", command=make_wisdom)
    top.add_cascade(label="Дополнительно", menu=dop, underline=0)
    # make wisdom  в самом конце, чтобы не мeшaла.


def make_settings_sign():
    settings_sign = Toplevel()
    settings_frame1 = Frame(settings_sign)
    # Нужно ли растягивать сам фрейм?
    settings_frame1.pack(expand=YES, fill=X)
    settings_frame2 = Frame(settings_sign)
    settings_frame2.pack(expand=YES, fill=X)
    settings_frame3 = Frame(settings_sign)
    settings_frame3.pack(expand=YES, fill=X)
    global variable_ext
    variable_ext = StringVar()
    Label(settings_frame1,
          text="Тут вы можете выбрать расширение подписанного файла. \n Обычно при электронном взаимодействии необходимо расширение '.sig'. \n p7s используется в электронной почте, обычно генерируется с помощью других программ. \n '.sgn' используется редко").pack(
        side=LEFT, expand=YES)
    Radiobutton(settings_frame1, text=".sig", command=lambda: (SB.change_ext(".sig")), variable=variable_ext,
                value=".sig").pack(side=LEFT, expand=YES)
    Radiobutton(settings_frame1, text=".p7s", command=lambda: (SB.change_ext(".p7s")), variable=variable_ext,
                value=".p7s").pack(side=LEFT, expand=YES)
    Radiobutton(settings_frame1, text=".sgn", command=lambda: (SB.change_ext(".sgn")), variable=variable_ext,
                value=".sgn").pack(side=LEFT, expand=YES)
    variable_ext.set(SB.changed_ext)
    global variable_attach
    variable_attach = StringVar()
    Label(settings_frame2,
          text="Здесь вы можете выбрать формат электронной подписи:\n Откреплённая подпись - когда берётся оригинальный документ, делается слепок этого документа, далее подписывается этот слепок и сохраняется в отдельный файл. \n Прикреплённая подпись - то же самое, но получившаяся подпись 'сверху' добавляется к оригинальному документу").pack(
        side=LEFT, expand=YES)
    Radiobutton(settings_frame2, text="Откреплённая", command=lambda: (SB.change_attach("-detached")),
                variable=variable_attach, value="-detached").pack(side=LEFT, expand=YES)
    Radiobutton(settings_frame2, text="Прикреплённая", command=lambda: (SB.change_attach("-attached")),
                variable=variable_attach, value="-attached").pack(side=LEFT, expand=YES)
    variable_attach.set(SB.changed_attach)
    global variable_coding
    variable_coding = StringVar()
    Label(settings_frame3,
          text="Здесь можно выбрать кодировку финального подписанного сообщения. \n Обычно в электронном взаимодействии требуется DER-кодировка, это двоиный формат хранения подписи. \n BASE64 чаще всего используется в пересылках электронной почты и специальных случаев.     ").pack(
        side=LEFT, expand=YES)
    Radiobutton(settings_frame3, text="DER", command=lambda: (SB.change_coding("-der")), variable=variable_coding,
                value="-der").pack(side=LEFT, expand=YES)
    Radiobutton(settings_frame3, text="BASE64", command=lambda: (SB.change_coding("BASE64")), variable=variable_coding,
                value="BASE64").pack(side=LEFT, expand=YES)
    variable_coding.set(SB.changed_coding_sig)


################### Всё, что связано с настройками сертификатов --------------------- НАЧАЛО

# Эта функция рисует новое окно и вызывает службу сертификатов
def make_see_cert():
    see_cert = Toplevel()
    info_cert = subprocess.Popen((r'C:\Users\Izyurov-aa\Desktop\Проект Z\certmgr', "-list"), stdout=subprocess.PIPE)
    info_cert_comm = info_cert.communicate()
    info_cert_comm[0].decode(encoding="cp866")
    print(info_cert_comm[0].decode(encoding="cp866"))

    # Эта здоровенная функция ест информацию из трубы cryptcp и парсит её в лист листов со значениями из сертификатов
    def make_see_cert_parser(text_on_parse):
        text_on_parse_list = text_on_parse.split("-------")
        list_of_CN = []
        for i in text_on_parse_list:
            #            print(i[i.find(" CN=",i.find("Subject")):i.find(",",i.find(" CN=",i.find("Subject"))) or i.find("\n",i.find(" CN=",i.find("Subject"))) ])
            text_on_parse_list_list = i.split("\n")
            for k in text_on_parse_list_list:
                if k.__contains__("Subject"):
                    k_finded_CN = k.find("CN=")
                    K_finded_CN_comma = k.find(",", k_finded_CN)
                    if K_finded_CN_comma - k_finded_CN > 50:
                        text_on_parse_list_list_itog = k[k.find("CN"):]
                        list_of_CN.append(text_on_parse_list_list_itog)
                    else:
                        list_of_CN.append(k[k_finded_CN:K_finded_CN_comma])
        list_of_issuer_CN = []
        for i in text_on_parse_list:
            text_on_parse_list_list = i.split("\n")
            for k in text_on_parse_list_list:
                if k.__contains__("Issuer"):
                    k_finded_CN = k.find("CN=")
                    K_finded_CN_comma = k.find(",", k_finded_CN)
                    if K_finded_CN_comma - k_finded_CN > 50:
                        text_on_parse_list_list_itog = k[k.find("CN"):]
                        list_of_issuer_CN.append(text_on_parse_list_list_itog)
                    else:
                        list_of_issuer_CN.append(k[k_finded_CN:K_finded_CN_comma])

        list_of_SN_and_G = []
        for i in text_on_parse_list:
            text_on_parse_list_list = i.split("\n")
            for k in text_on_parse_list_list:
                if k.__contains__("Subject"):
                    k_finded_SN = k.find("SN=")
                    k_finded_SN_comma = k.find(",", k.find("SN="))
                    k_finded_G = k.find("G")
                    k_finded_G_comma = k.find(",", k.find("G"))
                    kk = k[k_finded_SN:k_finded_SN_comma] + k[k_finded_G:k_finded_G_comma]
                    list_of_SN_and_G.append(kk)
        list_of_not_valid = []
        for i in text_on_parse_list:
            text_on_parse_list_list = i.split("\n")
            for k in text_on_parse_list_list:
                if k.__contains__("Not valid after"):
                    NVA = k.split(":")
                    NVA_cleared = ":".join(NVA[1:])
                    list_of_not_valid.append(NVA_cleared)
        list_of_print = []
        for i in text_on_parse_list:
            text_on_parse_list_list = i.split("\n")
            for k in text_on_parse_list_list:
                if k.__contains__("SHA1 Hash"):
                    print_number = k.split(":")
                    print_number__cleared = print_number[1].strip()
                    list_of_print.append(print_number__cleared)
        make_see_cert_parser_final = list(
            zip(list_of_CN, list_of_SN_and_G, list_of_issuer_CN, list_of_not_valid, list_of_print))
        make_see_cert_parser_final_list = []
        make_see_cert_parser_final_list_list = []
        for i in make_see_cert_parser_final:
            for j in i:
                j = j.strip()
                if j.__contains__("G="):
                    j = j.replace("G=", " ")
                if j.__contains__("CN="):
                    j = j.replace("CN=", "")
                if j.__contains__("SN="):
                    j = j.replace("SN=", "")
                make_see_cert_parser_final_list.append(j)
            make_see_cert_parser_final_list_list.append(make_see_cert_parser_final_list)
            make_see_cert_parser_final_list = []
        return make_see_cert_parser_final_list_list

    # Тут парсер вывода: поля в пипе - ниже строчкой вход, выше - сама функция

    make_see_cert_strings = make_see_cert_parser(info_cert_comm[0].decode(encoding="cp866"))

    # Эта функция рисует и заполняет 5 полей Listbox. Попробую тут же сделать и бинд, и систему с выбором сертификата. Потом итог будет вести к изменениею SB.thumb = new. И всплывающее окно о выборе итоговом.
    def make_see_cert_drow(make_see_cert_strings, see_cert):
        kkkk = 0
        list_of_Listboxes = []
        make_see_cert_drow_top = ("Кому выдан", "Владелец", "Издатель", "Годен до", "Отпечаток")

        for i in range(5):
            LF = Frame(see_cert, )
            LF.pack(side=LEFT, expand=YES, fill=Y)
            Label(LF, text=make_see_cert_drow_top[i]).pack(side=TOP, anchor=W)
            listt = Listbox(LF, width=40)
            listt.pack(side=TOP, expand=YES, fill=BOTH)
            for j in range(len(make_see_cert_strings)):
                listt.insert(kkkk, make_see_cert_strings[j][i])
                kkkk += 1
            list_of_Listboxes.append(listt)
        kkkk = 0
        print(list_of_Listboxes)

        # Попался на ошибке новичка, Лутц писал об этом - после pack() возвращается None, а не фрейм. нельзятак не будет работаь

        def handlelist(event):
            # тут в цикле массово забиндить cur. во всех возможных вариантах. выбрать там, где в итоге и прозошёл счелчок.
            for i in list_of_Listboxes:
                cur_sel = i.curselection()
                if len(cur_sel) == 1:
                    handlelist_cur_sel_thumb = list_of_Listboxes[-1].get(cur_sel)
                    SB.change_cert(handlelist_cur_sel_thumb)
                    showinfo("Сертификат выбран",
                             "Сертификат выбран: {} \n Действует до {}".format(list_of_Listboxes[0].get(cur_sel),
                                                                               list_of_Listboxes[-2].get(cur_sel)))

        for f in list_of_Listboxes:
            f.config(selectmode=SINGLE, setgrid=1)
            f.bind('<Double-1>', handlelist)

    make_see_cert_drow(make_see_cert_strings, see_cert)


################### Всё, что связано с настройками сертификататов --------------------- КОНЕЦ ###################


# Это функция, рисующая меню настройки щшшифрования. Вход из "def makemenu(root)", строка 7.
def make_settings_enc():
    settings_enc = Toplevel()


# Эта функция о мудрости
list_of_seeing_wisdom = []


def make_wisdom():
    import random
    path_of_USERPROFILE = os.environ["USERPROFILE"]
    with_open = path_of_USERPROFILE + "\\" + "Wisdom.txt"
    with open(with_open, "r") as wisdom:
        w_l = wisdom.readlines()
        r_ch = random.choice(w_l)

        def make_wisdom_recursion(r_ch, list_of_seeing_wisdom):
            while r_ch not in list_of_seeing_wisdom:
                showinfo("О как!", r_ch)
                list_of_seeing_wisdom.append(r_ch)
                return
            r_ch = random.choice(w_l)
            make_wisdom_recursion(r_ch, list_of_seeing_wisdom)

        make_wisdom_recursion(r_ch, list_of_seeing_wisdom)


###################----- Всё, что связано с криптопровайдером ----- НАЧАЛО ###################

# Эта BIG-функция рисует меню Криптопровайдера + все функции внутри неё - отвечают за действия соответствующих кнопок и так вглубь.
def make_service_menu():
    fr1 = Toplevel()
    fr1.resizable(width=False, height=False)

    fr1.geometry("+{1}+{0}".format(str(int(root.winfo_screenheight() / 4)), str(int(root.winfo_screenwidth() / 4))))

    make_service_menu_kontainer = LabelFrame(fr1, text="Контейнер закрытого ключа")
    make_service_menu_kontainer.pack(side=TOP, fill=BOTH, padx=15)
    Label(make_service_menu_kontainer,
          text="Эти мастера позволяют протестировать, скопировать или удалить \n контейнер закрытого ключа с носителя.").pack(
        side=TOP, fill=BOTH, anchor=W)

    def make_service_menu_kontainer_testing():
        pass

    def make_service_menu_kontainer_copy():
        # make_service_menu_kontainer_copy_info = subprocess.Popen(<command>, std.out=PIPE)
        # Тут будет идти длинный блок парсинга выхода утилиты. В итоге должны выходить названия контейнеров!
        make_service_menu_kontainer_copy_fr = Toplevel()
        make_service_menu_kontainer_copy_fr_1 = Frame(make_service_menu_kontainer_copy_fr)
        make_service_menu_kontainer_copy_fr_1.pack(side=TOP, expand=YES, fill=BOTH)
        Label(make_service_menu_kontainer_copy_fr_1, text="Список ключевых контейнеров пользователя:").pack(side=TOP,
                                                                                                            anchor=W)

        make_service_menu_kontainer_copy_Listbox = Listbox(make_service_menu_kontainer_copy_fr_1, width=100)

        make_service_menu_kontainer_copy_Scrollbar = Scrollbar(make_service_menu_kontainer_copy_fr_1)
        make_service_menu_kontainer_copy_Scrollbar.config(command=make_service_menu_kontainer_copy_Listbox.yview)
        make_service_menu_kontainer_copy_Listbox.config(yscrollcommand=make_service_menu_kontainer_copy_Scrollbar.set)
        make_service_menu_kontainer_copy_Listbox.pack(side=LEFT, expand=YES, fill=BOTH)
        make_service_menu_kontainer_copy_Scrollbar.pack(side=RIGHT, fill=BOTH)
        make_service_menu_kontainer_copy_args = ["/opt/cprocsp/bin/amd64/csptest", "-keyset", "-enum_cont", "-fqcn",
                                                 "-verifyc", "|", "iconv", "-f", "cp1251"]
        seeee__all_kont = subprocess.Popen(make_service_menu_kontainer_copy_args, stdout=PIPE)

    def see_all_kont(make_service_menu_kontainer_copy_args):
        seeee__all_kont = subprocess.Popen(make_service_menu_kontainer_copy_args, stdout=PIPE)
        s = seeee__all_kont.communicate()
        decoded_s = s[0].decode(encoding="cp866")

    print(decoded_s)
    see_all_kont(make_service_menu_kontainer_copy_args)
    make_service_menu_kontainer_copy_Listbox.insert(0,
                                                    "Тут оочень длиннноооооооооооооооооооооооооооое название контейнера будет сокрее всего")

    def make_service_menu_kontainer_copy_selectSOURCE():
        index = make_service_menu_kontainer_copy_Listbox.curselection()
        make_service_menu_kontainer_copy_selectSOURCE_src = make_service_menu_kontainer_copy_Listbox.get(index)
        # Тут возможно надо будет распарсить название. взять именно часть с названием, без названия контейнера
        make_service_menu_kontainer_copy_selectSOURCE_Toplevel = Toplevel()
        make_service_menu_kontainer_copy_selectSOURCE_Toplevel_fr_1 = Frame(
            make_service_menu_kontainer_copy_selectSOURCE_Toplevel)
        make_service_menu_kontainer_copy_selectSOURCE_Toplevel_fr_1.pack(side=TOP)

        # Тут надо вызвать процесс и накидать в строку? (список(кортеж)) доступные места назначения. Пока в режиме теста 'тестовый кортеж'
        test_tuple = (
        "\\.\Aktiv Rutoken ECP 03", "\\rutoken_ecp_351d6671", "\\.\Different Aktiv ", "\\.\Aktiv Rutoken ECP 00 00",
        "\\.\Aktiv Rutoken ECP 00", "\\.\Aktiv Jacarta 00 00")

        def make_service_menu_kontainer_copy_selectDestination(j):
            for k in list_of_btn_fr_2:
                k.destroy()
            for i in list_of_btn_fr_1:
                i[0].config(background="white")
                if i[1] == j:
                    i[0].config(background="#4169E1")
            # Тут сверху хитренький проход цикла, перекрасивающий именно ту кнопку, на которую нажали. Все остальные перекрашиваются по дефолту в белый
            label = Label(make_service_menu_kontainer_copy_selectSOURCE_Toplevel_fr_2,
                          text="Укажите имя создаваемого контейнера:")
            label.pack(side=TOP, anchor=W)
            ent = Entry(make_service_menu_kontainer_copy_selectSOURCE_Toplevel_fr_2)
            ent.insert(0, make_service_menu_kontainer_copy_selectSOURCE_src + " - Copy")  # записать текст
            ent.pack(side=TOP, fill=X)
            list_of_btn_fr_2.append(label)
            list_of_btn_fr_2.append(ent)
            ent.focus()
            entry_name = ent.get()

            btn_2 = Button(make_service_menu_kontainer_copy_selectSOURCE_Toplevel_fr_3, text="Отмена",
                           command=make_service_menu_kontainer_copy_selectSOURCE_Toplevel.destroy)

            def make_service_menu_kontainer_copy_selectDestination_end():
                # Тут надо собрать аргументы утилиты в строку или итератор - и запихнуть её в Popen. Не забыть, что это будет: \
                # command -src make_service_menu_kontainer_copy_selectSOURCE_src (тут полное нужно!) -dst (j)+ (entry_name) + что-то ещё наверно
                # subprocess.Popen(<commnd>,std.out=PIPE)
                # Тут парсим выход. Если всё норм - showinfo что норм. В другом случае - другое шоу.
                # И всё!
                showinfo("Успех", "Контейнер скопирован!")
                make_service_menu_kontainer_copy_selectSOURCE_Toplevel.destroy()
                make_service_menu_kontainer_copy_fr.destroy()

            btn_1 = Button(make_service_menu_kontainer_copy_selectSOURCE_Toplevel_fr_3, text="Ок",
                           command=make_service_menu_kontainer_copy_selectDestination_end)
            btn_2.pack(side=RIGHT)
            btn_1.pack(side=RIGHT)
            list_of_btn_fr_2.append(btn_2)
            list_of_btn_fr_2.append(btn_1)

        Label(make_service_menu_kontainer_copy_selectSOURCE_Toplevel_fr_1,
              text="Выберите контейнер для копирования:").pack(side=TOP, anchor=W)
        make_service_menu_kontainer_copy_selectSOURCE_Toplevel_fr_2 = Frame(
            make_service_menu_kontainer_copy_selectSOURCE_Toplevel)
        make_service_menu_kontainer_copy_selectSOURCE_Toplevel_fr_2.pack(side=TOP, fill=BOTH)
        make_service_menu_kontainer_copy_selectSOURCE_Toplevel_fr_3 = Frame(
            make_service_menu_kontainer_copy_selectSOURCE_Toplevel)
        make_service_menu_kontainer_copy_selectSOURCE_Toplevel_fr_3.pack(side=BOTTOM)
        # Тут два списка. Первый содержит будущие кнопки в нижнем фреме - хранит объекты созданные, чтобы их в будущем можно было удалить при нажатии на следуюущую кнопку.
        # Второй список хранит ссылки и текст кнопок в верхнем фрейме. Чтобы можно было после нажатии на кнопку (функция - make_service_menu_kontainer_copy_selectDestination) по переданному через Лямбду тексту найти кнопку и обраившись к ней перекрасить её.
        list_of_btn_fr_2 = []
        list_of_btn_fr_1 = []
        for j in test_tuple:
            b = Button(make_service_menu_kontainer_copy_selectSOURCE_Toplevel_fr_1, text=j, bg="white",
                       activebackground="#4169E1",
                       command=(lambda j=j: make_service_menu_kontainer_copy_selectDestination(j)))
            tuple_b = (b, j)
            b.pack(side=RIGHT, padx=10, pady=10)

            list_of_btn_fr_1.append(tuple_b)
        print(list_of_btn_fr_1)
        # csptest -keycopy -src cont '\\.\FLASH\qwerty' -d cont '\\.\HDIMAGE\qwerty1

    make_service_menu_kontainer_copy_fr_2 = Frame(make_service_menu_kontainer_copy_fr)
    make_service_menu_kontainer_copy_fr_2.pack(side=BOTTOM, fill=BOTH)
    Button(make_service_menu_kontainer_copy_fr_2, text="Отмена",
           command=make_service_menu_kontainer_copy_fr.destroy).pack(side=RIGHT)
    Button(make_service_menu_kontainer_copy_fr_2, text="Выбрать",
           command=make_service_menu_kontainer_copy_selectSOURCE).pack(side=RIGHT)


def make_service_menu_kontainer_delete():
    make_service_menu_kontainer_delete_fr = Toplevel()

    make_service_menu_kontainer_delete_fr_1 = Frame(make_service_menu_kontainer_delete_fr)
    make_service_menu_kontainer_delete_fr_1.pack(side=TOP, expand=YES, fill=BOTH)

    Label(make_service_menu_kontainer_delete_fr_1, text="Список ключевых контейнеров пользователя:").pack(side=TOP,
                                                                                                          anchor=W)
    make_service_menu_kontainer_delete_Listbox = Listbox(make_service_menu_kontainer_delete_fr_1, width=100)
    make_service_menu_kontainer_delete_Scrollbar = Scrollbar(make_service_menu_kontainer_delete_fr_1)
    make_service_menu_kontainer_delete_Scrollbar.config(command=make_service_menu_kontainer_delete_Listbox.yview)
    make_service_menu_kontainer_delete_Listbox.config(yscrollcommand=make_service_menu_kontainer_delete_Scrollbar.set)
    make_service_menu_kontainer_delete_Listbox.pack(side=LEFT, expand=YES, fill=BOTH)
    make_service_menu_kontainer_delete_Scrollbar.pack(side=RIGHT, fill=BOTH)

    make_service_menu_kontainer_delete_Listbox.insert(0,
                                                      "Тут оочень длиннноооооооооооооооооооооооооооое название контейнера будет сокрее всего")

    make_service_menu_kontainer_delete_fr_2 = Frame(make_service_menu_kontainer_delete_fr)
    make_service_menu_kontainer_delete_fr_2.pack(side=BOTTOM, fill=BOTH)
    Button(make_service_menu_kontainer_delete_fr_2, text="Отмена",
           command=make_service_menu_kontainer_delete_fr.destroy).pack(side=RIGHT)

    def make_service_menu_kontainer_delete_selectDelete():
        index = make_service_menu_kontainer_delete_Listbox.curselection()
        container = make_service_menu_kontainer_delete_Listbox.get(index)
        if askokcancel("Удаление контейнера", "Удалить выбранный контейнер?"):
            # Тут надо вызвать подпроцесс, предварительно скормить ему аргументы. Среди них будет "container"
            # Потом нужно перезаписать видлеж List - снова вызвать процесс
            print("Удалено")
        else:
            pass

    Button(make_service_menu_kontainer_delete_fr_2, text="Выбрать",
           command=make_service_menu_kontainer_delete_selectDelete).pack(side=RIGHT)


Button(make_service_menu_kontainer, text="Протестировать...", command=make_service_menu_kontainer_testing).pack(
    side=LEFT, expand=YES)
Button(make_service_menu_kontainer, text="Скопировать...", command=make_service_menu_kontainer_copy).pack(side=LEFT,
                                                                                                          expand=YES)
Button(make_service_menu_kontainer, text="Удалить...", command=make_service_menu_kontainer_delete).pack(side=LEFT,
                                                                                                        expand=YES)

make_service_menu_sert = LabelFrame(fr1, text="Сертификаты в контейнере закрытого ключа")
make_service_menu_sert.pack(side=TOP, fill=BOTH, padx=15)
Label(make_service_menu_sert,
      text="Этот мастер позволяет просмотреть сертификаты, находящиеся в \nконтейнере закрытого ключа, и установить их в хранилище сертификатов.").pack(
    side=TOP, fill=BOTH, anchor=W)


def make_service_menu_sert_watchANDset():
    pass


Button(make_service_menu_sert, text="Просмотреть сертификаты  в контейнере...",
       command=make_service_menu_sert_watchANDset).pack(side=TOP, anchor=E)

make_service_menu_mycert = LabelFrame(fr1, text="Личный сертификат")
make_service_menu_mycert.pack(side=TOP, fill=BOTH, padx=15)
Label(make_service_menu_mycert,
      text="Этот мастер позволяет связать сертификат из файла с контейнером \n закрытого ключа, установив этот сертификат в храналище.").pack(
    side=TOP, fill=BOTH)


def make_service_menu_mycert_associate():
    pass


Button(make_service_menu_mycert, text="Установить личный сертификат...",
       command=make_service_menu_mycert_associate).pack(side=TOP, anchor=E)

make_service_menu_passOFkont = LabelFrame(fr1, text="Пароли закрытых ключей")
make_service_menu_passOFkont.pack(side=TOP, fill=BOTH, padx=15)
Label(make_service_menu_passOFkont,
      text="Эти мастера позволяют изменить пароли (ПИН-коды) закрытых \n ключей или удалить запомненные ранее пароли.").pack(
    side=TOP)  # Тут остановился. Доделать


def make_service_menu_passOFkont_chPASSW():
    pass


def make_service_menu_passOFkont_delPASSW():
    pass


Button(make_service_menu_passOFkont, text="Изменить пароль...", command=make_service_menu_passOFkont_chPASSW).pack(
    side=LEFT, expand=YES)
Button(make_service_menu_passOFkont, text="Удалить запомненные пароли...",
       command=make_service_menu_passOFkont_delPASSW).pack(side=RIGHT, expand=YES)


###################----- Всё, что связано с криптопровайдером ----- КОНЕЦ ###################

#  №№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№ КОНЕЦ функий, связанных с меню и всё что внутри него.  №№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№


# №№№№№№№№№№№№№№№№  Тут располагается всё что в главном меню. Первый класс - кнопка подписания и всё что с ней связано. НАЧАЛО  #№№№№№№№№№№№№№№№№

class SignButton(Button):
    def __init__(self, parent=None):
        Button.__init__(self, parent)
        self.config(text="Подписать файлы в текущей директории", fg='green', bg='black', font=('courier', 12),
                    relief=RAISED, bd=5)
        self.config(command=self.sign)
        self.pack(side=TOP, expand=YES, anchor=CENTER)
        self.count_of_signed_files = 0
        self.changed_ext = ".sig"
        self.changed_attach = "-detached"
        self.changed_coding_sig = "-der"
        self.changed_cert = "None"
        # Эти значения меняются из Настроек. По умоляанию знаечения как тут. cert Меняется с настроект сертификатов

        # функция ниже - самый огонь, она и подписывает файлы.

    def sign(self):
        exe = (r"C:\Users\Izyurov-aa\Desktop\Проект Z\cryptcp.exe",)
        list_of_files = []
        files = os.listdir(path='.')
        for i in files:
            if i != os.path.basename(__file__):
                if self.changed_coding_sig == "-der":
                    list_of_files.append(("-sign", self.changed_attach, "-uMy", "-thumbprint", self.changed_cert,
                                          self.changed_coding_sig, "-strict", i, i + self.changed_ext))
                else:  # выше и ниже временно изменил на отпечаток. Кажется, есть проблема с единственностью выбранного сертификата. Ведь при dn= 'ФФИОО' может быть вырана несколько сертов
                    list_of_files.append(("-sign", self.changed_attach, "-uMy", "-thumbprint", self.changed_cert, i,
                                          i + self.changed_ext))
        for j in list_of_files:
            process = subprocess.Popen(exe + j, stdout=subprocess.PIPE)
            comm = process.communicate()
            decoded_comm = comm[0].decode(encoding="cp866")
            print(decoded_comm)
            if decoded_comm.find('[ErrorCode: 0x00000000]') == -1 or decoded_comm.find(
                    "Подписанное сообщение успешно создано.") == -1:
                showinfo("Неудача", "Во время подписи с файлом\n \n {} \n \n возникли проблемы".format(j[
                                                                                                           -2]))  # в случае не дер-кодинга менется длина строки. Поэтому нафигация по индуксу с начала плохая. Переделать.
            else:
                self.count_of_signed_files = self.count_of_signed_files + 1
        if len(list_of_files) == self.count_of_signed_files: showinfo("Успех", "Все файлы подписаны успешно")
        list_of_files = []
        files = []

    # Тут идёт блок методов над атрибутами подписи, изменяемых с помощью настроек
    def change_ext(self, switch):
        self.changed_ext = switch
        print(self.changed_ext)

    def change_attach(self, switch):
        self.changed_attach = switch
        print(self.changed_attach)

    def change_coding(self, switch):
        self.changed_coding_sig = switch
        print(self.changed_coding_sig)

    def change_cert(self, switch):
        self.changed_cert = switch
        print(self.changed_cert)


def fr2_about(parent):
    LF_1 = LabelFrame(fr2, text="Версия КриптоПРО")
    LF_1.pack(side=TOP, fill=BOTH)
    LF_1_f1 = Frame(LF_1)
    LF_1_f1.pack(side=LEFT, fill=BOTH)
    Label_version_l = Label(LF_1_f1, text="Версия продукта").pack(side=TOP, anchor=W)
    Label_version_2 = Label(LF_1_f1, text="Версия ядра СКЗИ").pack(side=TOP, anchor=W)
    LF_1_f2 = Frame(LF_1)
    LF_1_f2.pack(side=RIGHT, fill=BOTH)
    test_version_prod = "4.0.9606"
    test_version_yadra = "4.0.9002 КС1"
    Label(LF_1_f2, text=test_version_prod).pack(side=TOP, anchor=W)
    Label(LF_1_f2, text=test_version_yadra).pack(side=TOP, anchor=W)

    LF_2 = LabelFrame(fr2, text="Лицензия")
    LF_2.pack(side=TOP, fill=BOTH)
    LF_2_f1 = Frame(LF_2)
    LF_2_f1.pack(side=LEFT, fill=BOTH)
    LF_2_f1_text = ("Серийный номер", "Владелец", "Органинизация", "Срок действия", "Тип лицензии", "Первая установка")
    for i in LF_2_f1_text:
        Label(LF_2_f1, text=i).pack(side=TOP, anchor=W)
    LF_2_f2 = Frame(LF_2)
    LF_2_f2.pack(side=RIGHT, fill=BOTH)
    # for j in LF_2_f1_text:
    #   Label(LF_2_f2, text=j).pack(side=TOP, anchor=W)
    # В этой области нужно доделать, откуда будет браться информация - вызываться прога или откуда-то из системы.
    Label(LF_2_f2, text="fjdshjk5hij3jh5i34o5hol435345345").pack(side=TOP, anchor=W)
    Label(LF_2_f2, text="Артём Изюъюров Александрович").pack(side=TOP, anchor=W)
    Label(LF_2_f2, text="ГИКЦ").pack(side=TOP, anchor=W)

    def fr2_about_setlicense():
        fr2_about_setlicense_window = Toplevel()
        fr2_about_setlicense_window.geometry("400x200+{0}+{1}".format(str(int((root.winfo_screenwidth() / 2) - 400)),
                                                                      str(int((root.winfo_screenheight() / 2) - 200))))
        fr2_about_setlicense_window_Entry1 = Entry(fr2_about_setlicense_window)
        fr2_about_setlicense_window_Entry1.pack(side=TOP, fill=X)

        def fr2_about_setlicense_accept():
            text = fr2_about_setlicense_window_Entry1.get()
            # тут мы вызываем подпроцесс установки лицензии. По трубе проверяем либо вызываем проверку лицензии. Если всё норм, то новое значение записываем в главное окно.
            # А не добавить ли при запуске проги сразу проверку на лицензию? Чтобы гарантированно иметь актуальные данные?!!!

        btn = Button(fr2_about_setlicense_window, text="Ok", command=fr2_about_setlicense_accept).pack(side=TOP,
                                                                                                       anchor=W)

    Button(fr2, text="Установить лицензию", command=fr2_about_setlicense).pack(side=TOP, anchor=W)


if __name__ == '__main__':
    root = Tk()
    root.title("Signer")
    root.geometry('800x600+200+100')
    root.resizable(width=False, height=False)
    print(sys.platform)
    fr1 = Frame(root)
    fr1.pack(side=LEFT, expand=YES, fill=BOTH)

    fr2 = Frame(root)
    fr2.pack(side=RIGHT, fill=BOTH, pady=150, padx=20)
    SB = SignButton(fr1)
    makemenu(root)
    fr2_about(fr2)
    root.mainloop()

    """
    Основные направления развития:
    1 Доделать кнопку шифрования, настройки к ней.
    2 сделать функционал копирования контейнеров\установки сертификатов





    """
















