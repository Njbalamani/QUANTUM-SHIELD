from django import forms

from benchmarks.models import BenchmarkOperation


class QuickScanForm(forms.Form):
    name = forms.CharField(max_length=200)
    text = forms.CharField(widget=forms.Textarea(attrs={"rows": 4}))


class QuickBenchmarkForm(forms.Form):
    algorithm = forms.CharField(max_length=128)
    operation = forms.ChoiceField(choices=BenchmarkOperation.choices)
    iterations = forms.IntegerField(min_value=1, max_value=200, initial=10)
