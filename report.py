import time
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

doc = SimpleDocTemplate("form_letter.pdf",pagesize=letter,
                        rightMargin=72,leftMargin=72,
                        topMargin=72,bottomMargin=18)
Report=[]

introduction = 'Cisco has determined that  is at a High risk due to the observation of attacks on the newtork targetting hosts that may be vulnerable. These attacks and hosts require further investigation to help lower the risk.'

ptext = '<font size=12>%s</font>' % (introduction)
Report.append(Paragraph(ptext, styles["Justify"]))
Report.append(Spacer(1, 12))

logo = "malware_per_pc.png"
im = Image(logo, 3*inch, 3*inch)
Report.append(im)

vulnerability_desc = 'Vulnerability is a cyber-security term that refers to a flaw in a system that can leave it open to attack. A vulnerability may also refer to any type of weakness in a computer system itself, in a set of procedures, or in anything that leaves information security exposed to a threat.'

ptext = '<font size=12>%s</font>' % (vulnerability_desc)
Report.append(Paragraph(ptext, styles["Justify"]))
Report.append(Spacer(1, 12))

logo = 'vulnerability_per_pc.png'
im = Image(logo, 3*inch, 3*inch)
Report.append(im)

tags_desc = 'Tags below may describe the most important attack types observed in your network'
ptext = '<font size=12>%s</font>' % (tags_desc)
Report.append(Paragraph(ptext, styles["Justify"]))
Report.append(Spacer(1, 12))

logo = 'tags.png'
im = Image(logo, 3*inch, 3*inch)
Report.append(im)

title = "Top finding:"
ptext = '<font size=12>%s</font>' % (title)
Report.append(Paragraph(ptext, styles["Justify"]))
Report.append(Spacer(1, 12))

for desc in top_threat[1]:
    ptext = '<font size=12>%s</font>' % (desc)
    Report.append(Paragraph(ptext, styles["Justify"]))
    Report.append(Spacer(1, 12))
 
 
doc.build(Report)

