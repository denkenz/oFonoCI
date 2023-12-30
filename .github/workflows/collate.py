#!/usr/bin/python3
import os

def parse_results(directory):
    results = []

    for subdir, _, files in os.walk(directory):
        # Assuming 'name' is present in every subdirectory
        name_file = os.path.join(subdir, 'name')
        if os.path.exists(name_file):
            with open(name_file, 'r') as name_file:
                name = name_file.read().strip()

            result_entry = {'name': name, 'sections': []}

            for step in ['configure', 'build', 'unit', 'distcheck', 'stktest']:
                step_file = os.path.join(subdir, step)
                if os.path.exists(step_file):
                    with open(step_file, 'r') as step_file:
                        contents = step_file.read().split('\n', 1)
                        status = contents[0].strip()
                        output = contents[1] if len(contents) > 1 and contents[1] != '' else None

                    result_entry['sections'].append({
                        'step': step.capitalize(),
                        'status': status,
                        'output': output
                    })

            results.append(result_entry)

    return results

def write_email_file(results, output_file):
    with open(output_file, 'w') as email_file:
        for result_entry in results:
            name = result_entry['name']
            email_file.write(f"{name}\n")
            email_file.write('=' * len(name) + '\n')

            for section in result_entry['sections']:
                step = section['step']
                status = section['status']
                output = section['output']

                email_file.write(f"{step}: {status}\n")
                if output is not None:
                    email_file.write('    ' + output.replace('\n', '\n    '))

            email_file.write('\n')

        checkpatch_file = 'checkpatch-results.txt'
        if os.path.exists(checkpatch_file):
            checkpatch_heading = 'Checkpatch Output'
            email_file.write(checkpatch_heading + '\n')
            email_file.write('=' * len(checkpatch_heading) + '\n')
            with open(checkpatch_file, 'r') as checkpatch_file:
                checkpatch_output = checkpatch_file.read()
                email_file.write(checkpatch_output)

if __name__ == "__main__":
    results_directory = 'results'
    email_file_name = 'email.txt'

    results = parse_results(results_directory)
    write_email_file(results, email_file_name)

