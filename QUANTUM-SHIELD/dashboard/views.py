from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.utils.decorators import method_decorator
from django.views.generic import TemplateView, View

from core.crypto import get_oqs, oqs_version

from .forms import QuickBenchmarkForm, QuickScanForm
from .services import get_dashboard_data


class LandingView(TemplateView):
    template_name = "home.html"

    def dispatch(self, request, *args, **kwargs):
        if getattr(request.user, "is_authenticated", False):
            return redirect("dashboard:dashboard")
        return super().dispatch(request, *args, **kwargs)


@method_decorator(login_required(login_url="/login/"), name="dispatch")
class DashboardView(TemplateView):
    template_name = "dashboard/index.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(get_dashboard_data(self.request.user))
        context.setdefault("scan_form", QuickScanForm())
        context.setdefault("benchmark_form", QuickBenchmarkForm())
        return context

    def post(self, request, *args, **kwargs):
        if "scan_submit" in request.POST:
            form = QuickScanForm(request.POST)
            if form.is_valid():
                try:
                    from scanner.services import scan_text
                except (ImportError, AttributeError) as exc:
                    messages.error(request, "Scanning is unavailable: {0}".format(exc))
                else:
                    try:
                        scan_text(
                            form.cleaned_data["text"],
                            name=form.cleaned_data["name"],
                            created_by=request.user,
                            request=request,
                        )
                        messages.success(request, "Scan completed successfully.")
                        return redirect("dashboard:dashboard")
                    except Exception as exc:
                        messages.error(request, "Scan failed: {0}".format(exc))
            else:
                messages.error(request, "Please correct the scan form errors.")
            return render(
                request,
                self.template_name,
                self.get_context_data(scan_form=form, benchmark_form=QuickBenchmarkForm()),
            )

        if "benchmark_submit" in request.POST:
            form = QuickBenchmarkForm(request.POST)
            if form.is_valid():
                try:
                    from benchmarks.services import create_benchmark_run
                except (ImportError, AttributeError) as exc:
                    messages.error(request, "Benchmarking is unavailable: {0}".format(exc))
                else:
                    try:
                        create_benchmark_run(
                            algorithm=form.cleaned_data["algorithm"],
                            operation=form.cleaned_data["operation"],
                            iterations=form.cleaned_data["iterations"],
                            requested_by=request.user,
                            request=request,
                        )
                        messages.success(request, "Benchmark completed successfully.")
                        return redirect("dashboard:dashboard")
                    except Exception as exc:
                        messages.error(request, "Benchmark failed: {0}".format(exc))
            else:
                messages.error(request, "Please correct the benchmark form errors.")
            return render(
                request,
                self.template_name,
                self.get_context_data(scan_form=QuickScanForm(), benchmark_form=form),
            )

        messages.error(request, "Unknown dashboard action.")
        return redirect("dashboard:dashboard")


class HealthView(View):
    def get(self, request, *args, **kwargs):
        try:
            module = get_oqs()
            available = module is not None
            version = oqs_version() if available else None
        except Exception:
            available = False
            version = None
        try:
            counts = get_dashboard_data().get("counts", {})
        except Exception:
            counts = {}
        return JsonResponse(
            {
                "status": "ok",
                "oqs_available": available,
                "oqs_version": version,
                "counts": counts,
            }
        )
