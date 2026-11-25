from celery import shared_task

from .models import BenchmarkRun
from .services import run_benchmark


@shared_task(name="benchmarks.run_benchmark")
def run_benchmark_task(run_id):
    try:
        run = BenchmarkRun.objects.get(pk=run_id)
    except BenchmarkRun.DoesNotExist:
        return None
    return run_benchmark(run)
