from django import forms

class UploadFileForm(forms.Form):
    exe_file = forms.FileField(label="Upload an .exe file")