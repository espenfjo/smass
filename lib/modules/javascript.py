

class javascript(object):
    def __init__(self, artifact):
        self.type = "javascript"
        self.artifact = artifact.data
        self.data = {}
        self.data["name"] = "JavaScript"
        self.data["_model"] = self.data["name"]
        self.data["_module"] = "analysis.models"

    def init(self):
        g = JSMedian(self.artifact)        
        self.data[''] = g.data



# Borrowed from Alexander Hanel
# Seehttp://hooked-on-mnemonics.blogspot.no/2013/02/detecting-pdf-js-obfuscation-using.html
        
from StringIO import StringIO
import numpy as num 
import jsbeautifier

class JSMedian():
    def __init__(self, artifact):
        self.fullData = ''
        self.bjs = False
        self.PS = True
        self.plotData = []
        self.x = []
        self.y = []
        self.data = {}
        self.process(artifact)
        if num.mean(self.y)/num.median(self.y) > 2:
            self.data = {"mean": num.mean(self.y), "median": num.median(self.y)}            


    def beautifier(self, buffer):
        'clean up the JS'
        try:
            temp = jsbeautifier.beautify(buffer.read())
        except Exception, e:
            logging.error("ERROR: jsbeautifier: {}".format(e))
            return
        return temp 
    
    def process(self,data):
        'disneyland'
        if self.bjs == True:
            data = self.beautifier(data)
        if not data:
            return
        if type(data) is str:
            data = StringIO(data)
        self.fullData = data.readlines()
        # clean up JS that is all one line 
        if len(self.fullData) == 1 or self.PS == True:
            self.PS = False
            self.bjs = True
            data.seek(0)
            self.process(data)
        for t in range(len(self.fullData)): self.x.append(t)
        for t in self.fullData : self.y.append(len(t))
