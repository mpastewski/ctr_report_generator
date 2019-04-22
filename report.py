from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

doc = SimpleDocTemplate("pov_report.pdf",pagesize=letter,
                        rightMargin=72,leftMargin=72,
                        topMargin=72,bottomMargin=18)
Report=[]

styles = getSampleStyleSheet()
styleN = styles['Normal']
styleH = styles['Heading1']

Report.append(Paragraph("Introduction", styleH))
Report.append(Spacer(1, 12))

introduction = 'Cisco has determined that  is at a High risk due to the observation of attacks on the newtork targetting hosts that may be vulnerable. These attacks and hosts require further investigation to help lower the risk.'
ptext = '<font size=12>%s</font>' % (introduction)
Report.append(Paragraph(ptext, styleN))
Report.append(Spacer(1, 12))

logo = "malware_per_pc.png"
im = Image(logo, 3.5*inch, 3.5*inch)
Report.append(im)
Report.append(Spacer(1, 12))

text = '<font size=12>Infections detected: %s</font>' % (len(list_of_malware))
Report.append(Paragraph(ptext, styleN))
Report.append(Spacer(1, 12))

vulnerability_desc = 'Vulnerability is a cyber-security term that refers to a flaw in a system that can leave it open to attack. A vulnerability may also refer to any type of weakness in a computer system itself, in a set of procedures, or in anything that leaves information security exposed to a threat.'

ptext = '<font size=12>%s</font>' % (vulnerability_desc)
Report.append(Paragraph(ptext, styleN))
Report.append(Spacer(1, 12))


logo = 'vulnerability_per_pc.png'
im = Image(logo, 3.5*inch, 3.5*inch)
Report.append(im)
Report.append(Spacer(1, 12))
Report.append(Spacer(1, 12))

tags_desc = 'Tags below may describe the most important attack types observed in your network'
ptext = '<font size=12>%s</font>' % (tags_desc)
Report.append(Paragraph(ptext, styleN))
Report.append(Spacer(1, 12))

logo = 'tags.png'
im = Image(logo, 3.5*inch, 3.5*inch)
Report.append(im)
Report.append(Spacer(1, 12))


Report.append(Paragraph("Top finding:", styleH))
Report.append(Spacer(1, 12))

ptext = '<font size=12>SHA256: %s</font>' % (sha256)
Report.append(Paragraph(ptext, styleN))
Report.append(Spacer(1, 12))

title = "Threat Intelligence:"
ptext = '<font size=12>%s</font>' % (title)
Report.append(Paragraph(ptext, styleH))
Report.append(Spacer(1, 12))


for key,value in top_threat[0].items():
    ptext = '<font size=12>%s: %s</font>' % (key, value)
    Report.append(Paragraph(ptext, styleN))
Report.append(Spacer(1, 12))




title = "Behavioral Indicators:"
ptext = '<font size=12>%s</font>' % (title)
Report.append(Paragraph(ptext, styleH))
Report.append(Spacer(1, 12))

for desc in top_threat[1]:
    ptext = '<font size=12>%s</font>' % (desc)
    Report.append(Paragraph(ptext, styleN))
    Report.append(Spacer(1, 12))

doc.build(Report)

