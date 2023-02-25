class saveToFile:
    def __init__(self, fileSavePath, suffix=""):
        self.fileSavePath = fileSavePath          # excel的保存路径
        self.file =open("{}{}".format(fileSavePath,suffix),'a', encoding="utf-8")                        # openpyxl.Workbook()的实例话
        self.line = 1               # 表格的行

    def add(self, lines):
        if isinstance(lines,list):
            for line in lines:
                if isinstance(line,list):
                    self.file.writelines('|'.join(line))
                else:
                    self.file.writelines(line)
                self.file.write('\n')
        else:
            self.file.writelines(lines)
            self.file.write('\n')


