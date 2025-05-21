from django.shortcuts import render
from .forms import UploadFileForm
from .feature_extraction import extract_pe_features
import pickle
import pandas as pd
import os
import glob
from django.conf import settings


def load_model():
    model_path = os.path.join(settings.BASE_DIR, 'detector', 'model.pkl')
    with open(model_path, 'rb') as file:
        return pickle.load(file)


model = load_model()


def upload_file(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['exe_file']
            if not uploaded_file.name.lower().endswith('.exe'):
                return render(request, 'detector/upload.html', {
                    'form': form,
                    'error': 'Invalid file type (must be .exe)'
                })

            # Save the file
            temp_dir = os.path.join(settings.MEDIA_ROOT, 'uploads')
            os.makedirs(temp_dir, exist_ok=True)
            file_path = os.path.join(temp_dir, uploaded_file.name)
            with open(file_path, 'wb') as f:
                for chunk in uploaded_file.chunks():
                    f.write(chunk)

            return render(request, 'detector/upload.html', {
                'form': UploadFileForm(),
                'message': f'File "{uploaded_file.name}" uploaded successfully. Upload another or process all.'
            })
    else:
        form = UploadFileForm()
    return render(request, 'detector/upload.html', {'form': form})


def process_files(request):
    temp_dir = os.path.join(settings.MEDIA_ROOT, 'uploads')
    results = []

    # Get all .exe files, sorted by creation time (FIFO)
    exe_files = sorted(
        glob.glob(os.path.join(temp_dir, '*.exe')),
        key=os.path.getctime
    )

    for file_path in exe_files:
        filename = os.path.basename(file_path)
        features = extract_pe_features(file_path)
        if features is None:
            results.append({'filename': filename, 'result': 'Error processing file'})
        else:
            feature_order = ['numstrings', 'avlength', 'printables', 'entropy', 'MZ', 'size', 'vsize',
                             'has_debug', 'exports_counts', 'imports_counts', 'has_relocations',
                             'has_resources', 'has_signature', 'has_tls', 'symbols', 'coff.timestamp',
                             'optional.major_image_version', 'optional.minor_image_version',
                             'optional.major_linker_version', 'optional.minor_linker_version',
                             'optional.major_operating_system_version', 'optional.minor_operating_system_version',
                             'optional.major_subsystem_version', 'optional.minor_subsystem_version',
                             'optional.sizeof_code', 'optional.sizeof_headers', 'optional.sizeof_heap_commit']
            df = pd.DataFrame([features])[feature_order]
            prediction = model.predict(df)[0]
            label = "Malware" if prediction >= 0.5 else "Benign"
            results.append({'filename': filename, 'result': label})

        # Clean up
        os.remove(file_path)

    return render(request, 'detector/results.html', {'results': results})