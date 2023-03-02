'''
Demo of the `--mutate-stdin` option in ecfuzz.
Binary formats such as images can be input to ecfuzz, mutated, and then output to stdout.
With `--mutate-stdin` enabled, a single mutation will be generated, and no coverage metrics will be collected.

This python script mutates image files using `ecfuzz --mutate-stdin`, and stores the output in `output/gif`.
An integer is used to seed the mutation engine, which is incremented after each mutation attempt.
The Pillow package is used to check images for validity, and the loop is repeated until 128 valid images are generated.
Changing the `input_format` will yield different visual effects in the resulting animation.

Install Dependencies:
    cargo install ecfuzz
    pip install Pillow

Docs:
    https://docs.rs/ecfuzz/latest/ecfuzz/mutator/index.html
    https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html#fully-supported-formats
'''

import os
import subprocess
import io

# install Pillow with pip
from PIL import Image

default_multiplier = {
    'dib': 0.025,
    'jpeg': 0.001,
    'jpeg2000': 0.0001,
    'png': 0.001,
    'sgi': 0.01,
    'tga': 0.03,
    'webp': 0.000001,
}

# config
fpath = 'examples/ecfuzz_logo.jpeg'
outdir = 'output/gif'
input_format = 'jpeg'
output_format = 'png'
multiplier = default_multiplier[input_format]
frame_count = 128
max_iterations = 100000
assert os.path.isfile(fpath), 'input file does not exist'
assert os.path.isdir(outdir), 'output directory does not exist'

# read image data
with open(fpath, 'rb') as f:
    img = f.read()

# convert filetype to input_format before mutating
outfile = io.BytesIO()
assert outfile.tell() == 0
convert = Image.open(io.BytesIO(img))
if convert.size[0] > 512 or convert.size[1] > 512:
    convert.thumbnail((512, 512))
convertcopy = convert.copy()
try:
    convertcopy.save(fp=outfile,
                     format=input_format,
                     lossless=True,
                     quality=95,
                     method=6,
                     exact=True)
except OSError as e:
    assert "cannot write mode RGBA" in str(e)
    convertcopy = convertcopy.convert('RGB')
    convertcopy.save(fp=outfile, format=input_format, quality=95, method=6)
outfile.seek(0)
img = outfile.read()

# cleanup tmpdir
for file in os.listdir(outdir):
    os.remove(outdir + os.path.sep + file)
assert len(os.listdir(outdir)) == 0

# mutate until 128 valid images are collected in the output_folder
seed = 0
while len(os.listdir(outdir)) < frame_count:
    seed += 1

    # run ecfuzz in a subprocess with an incrementing seed value
    args = ('ecfuzz', '--mutate-stdin', '--multiplier', str(multiplier),
            '--seed', str(seed))
    proc = subprocess.Popen(args,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE)

    # send image bytes to ecfuzz via stdin, and store the mutated output
    out, _err = proc.communicate(img)
    _ = proc.wait()

    if _err is not None:
        raise Exception("Mutation error")

    # skip mutations that are duplicates of the input.
    # if this happens often, try increasing the mutation multiplier
    if out == img:
        print(f'warning: duplicate {seed=}')
        continue

    # attempt to decode the mutation as a valid image file.
    # valid images are saved to the output_folder
    try:
        # converted = convert_from_bytes(out, single_file=True, fmt='jpeg', output_file=str(seed), output_folder=outdir)
        outimg = Image.open(io.BytesIO(out), mode='r')
        if outimg.mode != convertcopy.mode:
            outimg = outimg.convert(convertcopy.mode)
        outimg.save(fp=f'{os.path.join(outdir, str(seed))}.{output_format}',
                    format=output_format)
    except Exception:
        pass
    if seed > max_iterations:
        print(f'warning: hit mutation limit after {max_iterations} attempts')
        break

# collect filepaths of resulting mutations
frames = [
    Image.open(i)
    for i in sorted([os.path.join(outdir, f) for f in os.listdir(outdir)])
]

# save the animation frames as animated .png file
outname = os.path.join(os.path.dirname(outdir),
                       fpath.rsplit(os.path.sep, 1)[1].split('.')[0] + '.png')
outfile = Image.open(io.BytesIO(img))
outfile.save(outname,
             format="png",
             append_images=frames,
             save_all=True,
             duration=128,
             loop=0)
